//! IMAP SASL SCRAM-SHA-256 coroutine; supports both the non-IR and
//! SASL-IR (RFC 4959) flows.
//!
//! The mechanism itself lives in io-sasl: this coroutine holds the IMAP
//! half of the exchange, the `AUTHENTICATE SCRAM-SHA-256` command, the
//! continuation requests, the tagged response and the post-auth
//! follow-ups, and asks [`SaslScramSha256`] what to put in each
//! response. The salted password, the client proof and the
//! verification of the server signature are the mechanism's, and so is
//! the refusal of an exchange that ends before that verification ran.
//!
//! The client nonce travels with the credentials, an I/O-free coroutine
//! having no source of randomness; [`ImapClientStd::connect`] draws one
//! for credentials that carry none.
//!
//! [`ImapClientStd::connect`]: crate::client::ImapClientStd::connect
//!
//! SCRAM: <https://www.rfc-editor.org/rfc/rfc5802>
//! SCRAM-SHA-256: <https://www.rfc-editor.org/rfc/rfc7677>
//! SASL-IR: <https://www.rfc-editor.org/rfc/rfc4959>
//!
//! # Example
//!
//! ```rust,no_run
//! use std::{
//!     io::{Read, Write},
//!     net::TcpStream,
//! };
//!
//! use io_imap::{
//!     codec::fragmentizer::Fragmentizer,
//!     coroutine::{ImapCoroutine, ImapCoroutineState, ImapYield},
//!     rfc7677::auth_scram_sha_256::{ImapAuthScramSha256, ImapAuthScramSha256Options},
//! };
//! use io_sasl::{rfc5801::SaslGs2ChannelBinding, rfc5802::SaslScramCreds};
//! use secrecy::SecretString;
//!
//! // Ready stream needed (TCP-connected, TLS-negotiated)
//! let mut stream = TcpStream::connect("localhost:143").unwrap();
//!
//! let mut fragmentizer = Fragmentizer::new(50 * 1024 * 1024);
//! let mut buf = [0u8; 4096];
//!
//! // NOTE: a real client draws its nonce from a cryptographic source.
//! let creds = SaslScramCreds {
//!     username: "alice".into(),
//!     password: SecretString::from("secret"),
//!     nonce: b"fyko+d2lbbFgONRv9qkxdawL".to_vec(),
//!     channel_binding: SaslGs2ChannelBinding::Unsupported,
//! };
//!
//! let opts = ImapAuthScramSha256Options::default();
//! let mut coroutine = ImapAuthScramSha256::new(creds, opts);
//! let mut arg = None;
//!
//! let capability = loop {
//!     match coroutine.resume(&mut fragmentizer, arg.take()) {
//!         ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         ImapCoroutineState::Complete(Ok(capability)) => break capability,
//!         ImapCoroutineState::Complete(Err(err)) => panic!("{err}"),
//!     }
//! };
//!
//! println!("{capability:?}");
//! ```

use core::{fmt, mem};

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use imap_codec::{
    AuthenticateDataCodec, CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        auth::{AuthMechanism, AuthenticateData},
        command::{Command, CommandBody},
        core::{IString, NString, TagGenerator},
        response::{
            Capability, Code, CommandContinuationRequest, Data, StatusBody, StatusKind, Tagged,
        },
        secret::Secret,
    },
};
use io_sasl::{
    coroutine::*,
    rfc5802::{SaslScramCreds, SaslScramError},
    rfc7677::scram_sha_256::SaslScramSha256,
};
use log::{debug, trace};
use thiserror::Error;

use crate::{coroutine::*, imap_try, rfc2971::id::*, rfc3501::capability::*, send::*};

/// Failure causes during the SASL SCRAM-SHA-256 flow.
#[derive(Clone, Debug, Error)]
pub enum ImapAuthScramSha256Error {
    /// The server rejected authentication with a tagged NO.
    #[error("IMAP AUTHENTICATE SCRAM-SHA-256 failed: NO {0}")]
    No(String),
    /// The server rejected the AUTHENTICATE command with a tagged BAD.
    #[error("IMAP AUTHENTICATE SCRAM-SHA-256 failed: BAD {0}")]
    Bad(String),
    /// The server closed the connection with an untagged BYE.
    #[error("IMAP AUTHENTICATE SCRAM-SHA-256 failed: BYE {0}")]
    Bye(String),
    /// The server never returned the final tagged response.
    #[error("IMAP AUTHENTICATE SCRAM-SHA-256 failed: server did not return a tagged response")]
    MissingTagged,
    /// The server never sent the expected continuation request.
    #[error(
        "IMAP AUTHENTICATE SCRAM-SHA-256 failed: server did not send the expected continuation request"
    )]
    ExpectedContinuationRequest,
    /// The server returned OK before the mechanism could complete.
    #[error(
        "IMAP AUTHENTICATE SCRAM-SHA-256 failed: server returned OK before the mechanism could complete"
    )]
    UnexpectedOk,
    /// The mechanism refused the exchange.
    ///
    /// Every RFC 5802 failure lands here: a malformed server message, a
    /// server nonce that does not extend the client one, an error the
    /// server reported in place of its proof, a signature that does not
    /// match, and an exchange ending before that signature was checked
    /// at all.
    #[error("IMAP AUTHENTICATE SCRAM-SHA-256 failed: {0}")]
    Mechanism(#[from] SaslScramError),
    /// The underlying send coroutine failed.
    #[error("IMAP AUTHENTICATE SCRAM-SHA-256 failed: {0}")]
    Send(#[from] ImapSendError),
    /// The follow-up CAPABILITY command failed.
    #[error(transparent)]
    Capability(#[from] ImapCapabilityGetError),
    /// The follow-up ID command failed.
    #[error(transparent)]
    ServerId(#[from] ImapServerIdError),
}

/// Options for [`ImapAuthScramSha256::new`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImapAuthScramSha256Options {
    /// `true` selects SASL-IR (RFC 4959, inline client-first-message);
    /// `false` selects the non-IR upload-after-challenge flow.
    pub initial_request: bool,
    /// Fetch CAPABILITY after authentication when the tagged response
    /// carries no capability data. Defaults to `false`.
    pub ensure_capabilities: bool,
    /// Chain an RFC 2971 ID round-trip right after authentication, as
    /// required by some providers.
    ///
    /// Defaults to `None` (no ID); an empty list sends ID NIL.
    pub auto_id: Option<Vec<(IString<'static>, NString<'static>)>>,
}

/// I/O-free SASL SCRAM-SHA-256 coroutine.
pub struct ImapAuthScramSha256 {
    state: State,
    mechanism: SaslScramSha256,
    observed: Vec<Capability<'static>>,
    opts: ImapAuthScramSha256Options,
}

impl ImapAuthScramSha256 {
    /// Builds a SASL SCRAM-SHA-256 coroutine from `creds`.
    ///
    /// The credentials carry the client nonce, which must be printable
    /// ASCII without commas and which RFC 5802 wants drawn from at
    /// least 18 bytes of cryptographic randomness. It is an input
    /// rather than something drawn here, an I/O-free coroutine having
    /// no source of randomness, and it makes the exchange
    /// deterministically testable.
    ///
    /// They also carry the channel binding, which decides whether the
    /// exchange announces `SCRAM-SHA-256` or `SCRAM-SHA-256-PLUS`. This
    /// crate never asks a TLS session what it exported, so a caller
    /// wanting a bound exchange extracts the material itself.
    ///
    /// Depending on `opts.initial_request`, the client-first-message
    /// goes inline with the AUTHENTICATE command (SASL-IR) or is
    /// uploaded after the server challenge.
    pub fn new(creds: SaslScramCreds, opts: ImapAuthScramSha256Options) -> Self {
        Self {
            state: State::Start,
            mechanism: SaslScramSha256::new(creds),
            observed: Vec::new(),
            opts,
        }
    }

    // helper that tells if the coroutine needs to fetch capability or not (in
    // case found in data or untagged responses)
    fn wants_capability(
        &mut self,
        code: Option<Code<'static>>,
        data: Vec<Data<'static>>,
        untagged: Vec<StatusBody<'static>>,
    ) -> Option<State> {
        let mut new_capability = None;

        if let Some(Code::Capability(capability)) = code {
            new_capability.replace(capability);
        }

        for data in data {
            if let Data::Capability(capability) = data {
                new_capability.replace(capability);
            }
        }

        for StatusBody { code, .. } in untagged {
            if let Some(Code::Capability(capability)) = code {
                new_capability.replace(capability);
            }
        }

        if let Some(capability) = new_capability {
            self.observed = capability.into_iter().collect();
        }

        (self.opts.ensure_capabilities && self.observed.is_empty())
            .then(|| State::Capability(ImapCapabilityGet::new()))
    }

    // helper that tells if the coroutine needs to exchange ID with server
    fn wants_id(&mut self) -> Option<State> {
        let params = self.opts.auto_id.take()?;
        let wire = (!params.is_empty()).then_some(params);
        Some(State::Id(ImapServerId::new(ImapServerIdOptions {
            parameters: wire,
        })))
    }

    // helper that tells if the coroutine needs to send continuation auth data
    fn wants_continue(payload: Vec<u8>) -> State {
        let auth = AuthenticateData::r#continue(payload);
        let codec = AuthenticateDataCodec::new();
        State::Continue(ImapSend::new(codec, auth))
    }

    // helper that resumes SASL coroutine
    fn resume_sasl(
        &mut self,
        arg: SaslArg<'_>,
    ) -> Result<Option<Vec<u8>>, ImapAuthScramSha256Error> {
        match self.mechanism.resume(arg) {
            SaslCoroutineState::Yielded(SaslYield::WantsWrite(payload)) => Ok(Some(payload)),
            SaslCoroutineState::Yielded(SaslYield::WantsRead) => Ok(None),
            SaslCoroutineState::Complete(result) => result.map(|()| None).map_err(Into::into),
        }
    }
}

impl ImapCoroutine for ImapAuthScramSha256 {
    type Yield = ImapYield;
    type Return = Result<Vec<Capability<'static>>, ImapAuthScramSha256Error>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        loop {
            match &mut self.state {
                State::Start => {
                    let payload = match self.resume_sasl(SaslArg::None) {
                        Ok(payload) => payload,
                        Err(err) => return ImapCoroutineState::Complete(Err(err)),
                    };

                    // NOTE: the initial response travels inline only when the
                    // server was found to support RFC 4959, which is a decision
                    // taken before the exchange; otherwise it waits for the
                    // empty challenge.
                    let (initial_response, pending) = match payload {
                        Some(payload) if self.opts.initial_request => {
                            (Some(Secret::new(payload.into())), None)
                        }
                        payload => (None, payload),
                    };

                    let tag = TagGenerator::new().generate();
                    let body = CommandBody::Authenticate {
                        mechanism: AuthMechanism::ScramSha256,
                        initial_response,
                    };
                    let cmd = Command { tag, body };
                    trace!("send IMAP command {cmd:?}");

                    self.state = State::Send {
                        send: ImapSend::new(CommandCodec::new(), cmd),
                        pending,
                    };
                    debug!("{}", self.state);
                }
                State::Send { send, pending } => {
                    let out = imap_try!(send, fragmentizer, arg);

                    if let Some(bye) = out.bye {
                        let err = ImapAuthScramSha256Error::Bye(bye.text.to_string());
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    if let Some(cr) = out.continuation_request {
                        // NOTE: with the client-first-message still held back
                        // this is the empty challenge inviting it; with it
                        // already inlined the challenge is the
                        // server-first-message, which only the mechanism reads.
                        let payload = match pending.take() {
                            Some(payload) => payload,
                            None => {
                                match self.resume_sasl(SaslArg::Input(&extract_challenge(cr))) {
                                    Ok(payload) => payload.unwrap_or_default(),
                                    Err(err) => return ImapCoroutineState::Complete(Err(err)),
                                }
                            }
                        };

                        self.state = Self::wants_continue(payload);
                        debug!("{}", self.state);
                        continue;
                    }

                    let inlined = pending.is_none();

                    let Some(Tagged { body, .. }) = out.tagged else {
                        let err = ImapAuthScramSha256Error::ExpectedContinuationRequest;
                        return ImapCoroutineState::Complete(Err(err));
                    };

                    let code = match body.kind {
                        StatusKind::Ok if inlined => body.code,
                        StatusKind::Ok => {
                            let err = ImapAuthScramSha256Error::UnexpectedOk;
                            return ImapCoroutineState::Complete(Err(err));
                        }
                        StatusKind::No => {
                            let err = ImapAuthScramSha256Error::No(body.text.to_string());
                            return ImapCoroutineState::Complete(Err(err));
                        }
                        StatusKind::Bad => {
                            let err = ImapAuthScramSha256Error::Bad(body.text.to_string());
                            return ImapCoroutineState::Complete(Err(err));
                        }
                    };

                    // NOTE: a server ending the exchange this early proved
                    // nothing, and the mechanism says so rather than this
                    // crate guessing: SCRAM refuses every end that comes
                    // before it verified the server signature.
                    if let Err(err) = self.resume_sasl(SaslArg::Done) {
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    if let Some(next) = self.wants_capability(code, out.data, out.untagged) {
                        self.state = next;
                        debug!("{}", self.state);
                        continue;
                    }

                    if let Some(next) = self.wants_id() {
                        self.state = next;
                        debug!("{}", self.state);
                        continue;
                    }

                    let capability = mem::take(&mut self.observed);
                    return ImapCoroutineState::Complete(Ok(capability));
                }
                State::Continue(send) => {
                    let out = imap_try!(send, fragmentizer, arg);

                    if let Some(bye) = out.bye {
                        let err = ImapAuthScramSha256Error::Bye(bye.text.to_string());
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    if let Some(cr) = out.continuation_request {
                        let payload = match self.resume_sasl(SaslArg::Input(&extract_challenge(cr)))
                        {
                            Ok(payload) => payload.unwrap_or_default(),
                            Err(err) => return ImapCoroutineState::Complete(Err(err)),
                        };

                        self.state = Self::wants_continue(payload);
                        debug!("{}", self.state);
                        continue;
                    }

                    let Some(Tagged { body, .. }) = out.tagged else {
                        let err = ImapAuthScramSha256Error::MissingTagged;
                        return ImapCoroutineState::Complete(Err(err));
                    };

                    let code = match body.kind {
                        StatusKind::Ok => body.code,
                        StatusKind::No => {
                            let err = ImapAuthScramSha256Error::No(body.text.to_string());
                            return ImapCoroutineState::Complete(Err(err));
                        }
                        StatusKind::Bad => {
                            let err = ImapAuthScramSha256Error::Bad(body.text.to_string());
                            return ImapCoroutineState::Complete(Err(err));
                        }
                    };

                    // NOTE: the tagged OK ends the exchange, and the mechanism
                    // is told so rather than dropped. A server piggybacking
                    // its server-final-message on that OK instead of sending
                    // it as a continuation is refused here, where this crate
                    // used to accept it and report a success nobody verified.
                    if let Err(err) = self.resume_sasl(SaslArg::Done) {
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    if let Some(next) = self.wants_capability(code, out.data, out.untagged) {
                        self.state = next;
                        debug!("{}", self.state);
                        continue;
                    }

                    if let Some(next) = self.wants_id() {
                        self.state = next;
                        debug!("{}", self.state);
                        continue;
                    }

                    let capability = mem::take(&mut self.observed);
                    return ImapCoroutineState::Complete(Ok(capability));
                }
                State::Capability(capability) => {
                    self.observed = imap_try!(capability, fragmentizer, arg);

                    if let Some(next) = self.wants_id() {
                        self.state = next;
                        debug!("{}", self.state);
                        continue;
                    }

                    let capability = mem::take(&mut self.observed);
                    return ImapCoroutineState::Complete(Ok(capability));
                }
                State::Id(id) => {
                    imap_try!(id, fragmentizer, arg);
                    let capability = mem::take(&mut self.observed);
                    return ImapCoroutineState::Complete(Ok(capability));
                }
            }
        }
    }
}

enum State {
    Start,
    Send {
        send: ImapSend<CommandCodec>,
        pending: Option<Vec<u8>>,
    },
    Continue(ImapSend<AuthenticateDataCodec>),
    Capability(ImapCapabilityGet),
    Id(ImapServerId),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Start => f.write_str("start mechanism"),
            Self::Send { pending, .. } if pending.is_some() => f.write_str("send auth"),
            Self::Send { .. } => f.write_str("send auth with ir"),
            Self::Continue(_) => f.write_str("send response"),
            Self::Capability(_) => f.write_str("fetch capabilities"),
            Self::Id(_) => f.write_str("send id"),
        }
    }
}

fn extract_challenge(cr: CommandContinuationRequest<'static>) -> Vec<u8> {
    match cr {
        CommandContinuationRequest::Basic(basic) => basic.text().to_string().into_bytes(),
        CommandContinuationRequest::Base64(data) => data.as_ref().to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use core::str;

    use alloc::{borrow::ToOwned, format};

    use base64::{Engine, engine::general_purpose::STANDARD};
    use hmac::{Hmac, KeyInit, Mac};
    use io_sasl::rfc5801::SaslGs2ChannelBinding;
    use secrecy::SecretString;
    use sha2::Sha256;

    use crate::rfc7677::auth_scram_sha_256::*;

    type HmacSha256 = Hmac<Sha256>;

    const NONCE: &[u8] = b"fyko+d2lbbFgONRv9qkxdawL";

    fn creds() -> SaslScramCreds {
        SaslScramCreds {
            username: "alice".to_string(),
            password: SecretString::from("secret"),
            nonce: NONCE.to_vec(),
            channel_binding: SaslGs2ChannelBinding::Unsupported,
        }
    }

    #[test]
    fn ir_success_returns_ok() {
        let opts = ImapAuthScramSha256Options {
            initial_request: true,
            ..Default::default()
        };

        let mut auth = ImapAuthScramSha256::new(creds(), opts);
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut auth, &mut frag, None);
        let line = str::from_utf8(&bytes).expect("utf8 command");
        let tag = first_word(line).to_owned();
        let client_first = decode_last_base64_token(line);
        let client_nonce = extract_client_nonce(&client_first);

        expect_wants_read(&mut auth, &mut frag);

        let server_first = format!("r={client_nonce}ServerExtra,s={SALT_B64},i={ITERATIONS}");
        let challenge = format!("+ {}\r\n", STANDARD.encode(&server_first));
        let client_final_bytes =
            expect_wants_write(&mut auth, &mut frag, Some(challenge.as_bytes()));
        let client_final_line = str::from_utf8(&client_final_bytes).expect("utf8");
        let client_final = decode_last_base64_token(client_final_line.trim_end());

        expect_wants_read(&mut auth, &mut frag);

        let server_final = build_server_final(&client_first, &server_first, &client_final);
        let challenge2 = format!("+ {}\r\n", STANDARD.encode(&server_final));
        let ack = expect_wants_write(&mut auth, &mut frag, Some(challenge2.as_bytes()));
        assert_eq!(b"\r\n", &*ack);

        expect_wants_read(&mut auth, &mut frag);

        let reply = format!("{tag} OK AUTHENTICATE completed\r\n");
        expect_complete_ok(&mut auth, &mut frag, reply.as_bytes());
    }

    #[test]
    fn ir_server_error_returns_mechanism_error() {
        let opts = ImapAuthScramSha256Options {
            initial_request: true,
            ..Default::default()
        };

        let mut auth = ImapAuthScramSha256::new(creds(), opts);
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut auth, &mut frag, None);
        let client_first = decode_last_base64_token(str::from_utf8(&bytes).expect("utf8"));
        let client_nonce = extract_client_nonce(&client_first);

        expect_wants_read(&mut auth, &mut frag);

        let server_first = format!("r={client_nonce}ServerExtra,s={SALT_B64},i={ITERATIONS}");
        let challenge = format!("+ {}\r\n", STANDARD.encode(&server_first));
        let _client_final = expect_wants_write(&mut auth, &mut frag, Some(challenge.as_bytes()));

        expect_wants_read(&mut auth, &mut frag);

        let server_final = "e=invalid-proof";
        let challenge2 = format!("+ {}\r\n", STANDARD.encode(server_final));
        let err = expect_complete_err(&mut auth, &mut frag, challenge2.as_bytes());
        let ImapAuthScramSha256Error::Mechanism(SaslScramError::ServerError(text)) = err else {
            panic!("expected ImapAuthScramSha256Error::Mechanism, got {err:?}");
        };
        assert_eq!(text, "invalid-proof");
    }

    #[test]
    fn ir_tagged_bad_returns_bad_error() {
        let opts = ImapAuthScramSha256Options {
            initial_request: true,
            ..Default::default()
        };

        let mut auth = ImapAuthScramSha256::new(creds(), opts);
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut auth, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8"));

        expect_wants_read(&mut auth, &mut frag);

        let reply = format!("{tag} BAD AUTHENTICATE not enabled\r\n");
        let err = expect_complete_err(&mut auth, &mut frag, reply.as_bytes());
        let ImapAuthScramSha256Error::Bad(text) = err else {
            panic!("expected ImapAuthScramSha256Error::Bad, got {err:?}");
        };
        assert_eq!(text, "AUTHENTICATE not enabled");
    }

    #[test]
    fn ir_tagged_ok_before_the_server_proved_itself_returns_mechanism_error() {
        let opts = ImapAuthScramSha256Options {
            initial_request: true,
            ..Default::default()
        };

        let mut auth = ImapAuthScramSha256::new(creds(), opts);
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut auth, &mut frag, None);
        let line = str::from_utf8(&bytes).expect("utf8 command");
        let tag = first_word(line).to_owned();
        let client_first = decode_last_base64_token(line);
        let client_nonce = extract_client_nonce(&client_first);

        expect_wants_read(&mut auth, &mut frag);

        let server_first = format!("r={client_nonce}ServerExtra,s={SALT_B64},i={ITERATIONS}");
        let challenge = format!("+ {}\r\n", STANDARD.encode(&server_first));
        expect_wants_write(&mut auth, &mut frag, Some(challenge.as_bytes()));

        expect_wants_read(&mut auth, &mut frag);

        // NOTE: a tagged OK arriving in place of the
        // server-final-message ends the exchange with the server
        // signature unchecked, which the mechanism refuses. This crate
        // used to report it as a success.
        let reply = format!("{tag} OK AUTHENTICATE completed\r\n");
        let err = expect_complete_err(&mut auth, &mut frag, reply.as_bytes());
        let ImapAuthScramSha256Error::Mechanism(SaslScramError::ServerSignatureNotVerified) = err
        else {
            panic!("expected ImapAuthScramSha256Error::Mechanism, got {err:?}");
        };
    }

    #[test]
    fn non_ir_success_returns_ok() {
        let opts = ImapAuthScramSha256Options::default();
        let mut auth = ImapAuthScramSha256::new(creds(), opts);
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut auth, &mut frag, None);
        let line = str::from_utf8(&bytes).expect("utf8 command");
        let tag = first_word(line).to_owned();
        assert!(line.trim_end().ends_with("AUTHENTICATE SCRAM-SHA-256"));

        expect_wants_read(&mut auth, &mut frag);

        let client_first_bytes = expect_wants_write(&mut auth, &mut frag, Some(b"+ \r\n"));
        let client_first = decode_last_base64_token(
            str::from_utf8(&client_first_bytes)
                .expect("utf8")
                .trim_end(),
        );
        let client_nonce = extract_client_nonce(&client_first);

        expect_wants_read(&mut auth, &mut frag);

        let server_first = format!("r={client_nonce}ServerExtra,s={SALT_B64},i={ITERATIONS}");
        let challenge = format!("+ {}\r\n", STANDARD.encode(&server_first));
        let client_final_bytes =
            expect_wants_write(&mut auth, &mut frag, Some(challenge.as_bytes()));
        let client_final = decode_last_base64_token(
            str::from_utf8(&client_final_bytes)
                .expect("utf8")
                .trim_end(),
        );

        expect_wants_read(&mut auth, &mut frag);

        let server_final = build_server_final(&client_first, &server_first, &client_final);
        let challenge2 = format!("+ {}\r\n", STANDARD.encode(&server_final));
        let ack = expect_wants_write(&mut auth, &mut frag, Some(challenge2.as_bytes()));
        assert_eq!(b"\r\n", &*ack);

        expect_wants_read(&mut auth, &mut frag);

        let reply = format!("{tag} OK AUTHENTICATE completed\r\n");
        expect_complete_ok(&mut auth, &mut frag, reply.as_bytes());
    }

    #[test]
    fn non_ir_server_error_returns_mechanism_error() {
        let opts = ImapAuthScramSha256Options::default();
        let mut auth = ImapAuthScramSha256::new(creds(), opts);
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut auth, &mut frag, None);
        let _tag = first_word(str::from_utf8(&bytes).expect("utf8"));

        expect_wants_read(&mut auth, &mut frag);

        let client_first_bytes = expect_wants_write(&mut auth, &mut frag, Some(b"+ \r\n"));
        let client_first = decode_last_base64_token(
            str::from_utf8(&client_first_bytes)
                .expect("utf8")
                .trim_end(),
        );
        let client_nonce = extract_client_nonce(&client_first);

        expect_wants_read(&mut auth, &mut frag);

        let server_first = format!("r={client_nonce}ServerExtra,s={SALT_B64},i={ITERATIONS}");
        let challenge = format!("+ {}\r\n", STANDARD.encode(&server_first));
        let _client_final = expect_wants_write(&mut auth, &mut frag, Some(challenge.as_bytes()));

        expect_wants_read(&mut auth, &mut frag);

        let server_final = "e=invalid-proof";
        let challenge2 = format!("+ {}\r\n", STANDARD.encode(server_final));
        let err = expect_complete_err(&mut auth, &mut frag, challenge2.as_bytes());
        let ImapAuthScramSha256Error::Mechanism(SaslScramError::ServerError(text)) = err else {
            panic!("expected ImapAuthScramSha256Error::Mechanism, got {err:?}");
        };
        assert_eq!(text, "invalid-proof");
    }

    const SALT_B64: &str = "QSXCR+Q6sek8bf92";
    const ITERATIONS: u32 = 4096;

    fn expect_wants_write(
        cor: &mut ImapAuthScramSha256,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> Vec<u8> {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ImapAuthScramSha256, frag: &mut Fragmentizer) {
        match cor.resume(frag, None) {
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(cor: &mut ImapAuthScramSha256, frag: &mut Fragmentizer, reply: &[u8]) {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Complete(Ok(_)) => {}
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut ImapAuthScramSha256,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> ImapAuthScramSha256Error {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        }
    }

    fn first_word(line: &str) -> &str {
        line.split_whitespace()
            .next()
            .expect("first whitespace-separated token")
    }

    fn decode_last_base64_token(line: &str) -> String {
        let b64 = line
            .trim_end()
            .rsplit_terminator(char::is_whitespace)
            .next()
            .expect("token");
        let bytes = STANDARD.decode(b64).expect("valid base64");
        String::from_utf8(bytes).expect("valid utf8")
    }

    fn extract_client_nonce(client_first: &str) -> &str {
        client_first
            .rsplit_once("r=")
            .expect("client-first has r=")
            .1
    }

    /// The server-final-message a server holding the same password
    /// would send, computed here rather than by the mechanism under
    /// test, so that what verifies the signature is not what produced
    /// it.
    fn build_server_final(client_first: &str, server_first: &str, client_final: &str) -> String {
        let client_first_bare = client_first.strip_prefix("n,,").expect("gs2 header");
        let client_final_without_proof = client_final
            .rsplit_once(",p=")
            .expect("client-final has p=")
            .0;
        let auth_message =
            format!("{client_first_bare},{server_first},{client_final_without_proof}");
        let salt = STANDARD.decode(SALT_B64).expect("valid salt");

        // NOTE: SaltedPassword = PBKDF2(SHA-256, password, salt, iterations).
        let mut salted_password = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(b"secret", &salt, ITERATIONS, &mut salted_password);

        // NOTE: ServerKey = HMAC(SaltedPassword, "Server Key").
        let mut mac = HmacSha256::new_from_slice(&salted_password).unwrap();
        mac.update(b"Server Key");
        let server_key = mac.finalize().into_bytes();

        // NOTE: ServerSignature = HMAC(ServerKey, AuthMessage).
        let mut mac = HmacSha256::new_from_slice(&server_key).unwrap();
        mac.update(auth_message.as_bytes());
        let server_signature = mac.finalize().into_bytes();

        format!("v={}", STANDARD.encode(server_signature))
    }
}
