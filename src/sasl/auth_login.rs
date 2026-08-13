//! IMAP SASL LOGIN coroutine (legacy two-prompt mechanism, pre-IETF);
//! supports both the non-IR and SASL-IR (RFC 4959) flows.
//!
//! The mechanism itself lives in io-sasl: this coroutine holds the IMAP
//! half of the exchange, the `AUTHENTICATE LOGIN` command, the
//! continuation requests, the tagged response and the post-auth
//! follow-ups, and asks [`SaslLogin`] what to put in each response. So
//! the two prompts, their order and the refusal of a third one are the
//! mechanism's business, and nothing here knows LOGIN sends a username
//! before a password.
//!
//! Background: <https://datatracker.ietf.org/doc/html/draft-murchison-sasl-login>
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
//!     sasl::auth_login::{ImapAuthLogin, ImapAuthLoginOptions},
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negotiated)
//! let mut stream = TcpStream::connect("localhost:143").unwrap();
//!
//! let mut fragmentizer = Fragmentizer::new(50 * 1024 * 1024);
//! let mut buf = [0u8; 4096];
//!
//! let opts = ImapAuthLoginOptions::default();
//! let mut coroutine = ImapAuthLogin::new("alice", "secret", opts);
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
    vec,
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
    login::{SaslLogin, SaslLoginCreds, SaslLoginError},
};
use log::{debug, trace};
use secrecy::SecretString;
use thiserror::Error;

use crate::{coroutine::*, imap_try, rfc2971::id::*, rfc3501::capability::*, send::*};

/// Failure causes during the SASL LOGIN flow.
#[derive(Clone, Debug, Error)]
pub enum ImapAuthLoginError {
    /// The server rejected authentication with a tagged NO.
    #[error("IMAP AUTHENTICATE LOGIN failed: NO {0}")]
    No(String),
    /// The server rejected the AUTHENTICATE command with a tagged BAD.
    #[error("IMAP AUTHENTICATE LOGIN failed: BAD {0}")]
    Bad(String),
    /// The server closed the connection with an untagged BYE.
    #[error("IMAP AUTHENTICATE LOGIN failed: BYE {0}")]
    Bye(String),
    /// The server never returned the final tagged response.
    #[error("IMAP AUTHENTICATE LOGIN failed: server did not return a tagged response")]
    MissingTagged,
    /// The server never sent the expected continuation request.
    #[error(
        "IMAP AUTHENTICATE LOGIN failed: server did not send the expected continuation request"
    )]
    ExpectedContinuationRequest,
    /// The server returned OK before the mechanism could complete.
    #[error(
        "IMAP AUTHENTICATE LOGIN failed: server returned OK before the mechanism could complete"
    )]
    UnexpectedOk,
    /// The mechanism refused the exchange.
    ///
    /// A challenge arriving once LOGIN has nothing left to say lands
    /// here rather than in a framing error of this crate's, only the
    /// mechanism knowing how many prompts it answers.
    #[error("IMAP AUTHENTICATE LOGIN failed: {0}")]
    Mechanism(#[from] SaslLoginError),
    /// The underlying send coroutine failed.
    #[error("IMAP AUTHENTICATE LOGIN failed: {0}")]
    Send(#[from] ImapSendError),
    /// The follow-up CAPABILITY command failed.
    #[error(transparent)]
    Capability(#[from] ImapCapabilityGetError),
    /// The follow-up ID command failed.
    #[error(transparent)]
    ServerId(#[from] ImapServerIdError),
}

/// Options for [`ImapAuthLogin::new`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImapAuthLoginOptions {
    /// `true` selects SASL-IR (RFC 4959, inline username);
    /// `false` selects the non-IR two-prompt flow.
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

/// I/O-free SASL LOGIN coroutine.
pub struct ImapAuthLogin {
    state: State,
    mechanism: SaslLogin,
    observed: Vec<Capability<'static>>,
    opts: ImapAuthLoginOptions,
}

impl ImapAuthLogin {
    /// Builds a SASL LOGIN coroutine authenticating `user` with
    /// `password`.
    ///
    /// Depending on `opts.initial_request`, the username goes inline
    /// with the AUTHENTICATE command (SASL-IR) or is uploaded after
    /// the first server prompt; the password always follows a prompt.
    pub fn new(
        user: impl AsRef<str>,
        password: impl AsRef<str>,
        opts: ImapAuthLoginOptions,
    ) -> Self {
        let mechanism = SaslLogin::new(SaslLoginCreds {
            username: user.as_ref().to_string(),
            password: SecretString::from(password.as_ref().to_string()),
        });

        Self {
            state: State::Start,
            mechanism,
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
    fn resume_sasl(&mut self, arg: SaslArg<'_>) -> Result<Option<Vec<u8>>, ImapAuthLoginError> {
        match self.mechanism.resume(arg) {
            SaslCoroutineState::Yielded(SaslYield::WantsWrite(payload)) => Ok(Some(payload)),
            SaslCoroutineState::Yielded(SaslYield::WantsRead) => Ok(None),
            SaslCoroutineState::Complete(Ok(())) => Ok(None),
            SaslCoroutineState::Complete(Err(err)) => Err(err.into()),
        }
    }
}

impl ImapCoroutine for ImapAuthLogin {
    type Yield = ImapYield;
    type Return = Result<Vec<Capability<'static>>, ImapAuthLoginError>;

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
                    // first prompt.
                    let (initial_response, pending) = match payload {
                        Some(payload) if self.opts.initial_request => {
                            (Some(Secret::new(payload.into())), None)
                        }
                        payload => (None, payload),
                    };

                    let tag = TagGenerator::new().generate();
                    let body = CommandBody::Authenticate {
                        mechanism: AuthMechanism::Login,
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
                        let err = ImapAuthLoginError::Bye(bye.text.to_string());
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    if let Some(cr) = out.continuation_request {
                        // NOTE: the username prompt is the implicit
                        // empty challenge whose answer is the initial
                        // response, as RFC 4959 defines it, so it is
                        // answered from what the mechanism already
                        // yielded rather than fed back to it.
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

                    if let Some(Tagged { body, .. }) = out.tagged {
                        let err = match body.kind {
                            StatusKind::Ok => ImapAuthLoginError::UnexpectedOk,
                            StatusKind::No => ImapAuthLoginError::No(body.text.to_string()),
                            StatusKind::Bad => ImapAuthLoginError::Bad(body.text.to_string()),
                        };

                        return ImapCoroutineState::Complete(Err(err));
                    }

                    let err = ImapAuthLoginError::ExpectedContinuationRequest;
                    return ImapCoroutineState::Complete(Err(err));
                }
                State::Continue(send) => {
                    let out = imap_try!(send, fragmentizer, arg);

                    if let Some(bye) = out.bye {
                        let err = ImapAuthLoginError::Bye(bye.text.to_string());
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
                        let err = ImapAuthLoginError::MissingTagged;
                        return ImapCoroutineState::Complete(Err(err));
                    };

                    let code = match body.kind {
                        StatusKind::Ok => body.code,
                        StatusKind::No => {
                            let err = ImapAuthLoginError::No(body.text.to_string());
                            return ImapCoroutineState::Complete(Err(err));
                        }
                        StatusKind::Bad => {
                            let err = ImapAuthLoginError::Bad(body.text.to_string());
                            return ImapCoroutineState::Complete(Err(err));
                        }
                    };

                    // NOTE: the tagged OK ends the exchange, and the mechanism
                    // is told so rather than dropped: a mechanism performing
                    // mutual authentication refuses here when it verified
                    // nothing, which is what stops a success reply from
                    // standing in for a proof the server never gave.
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
        CommandContinuationRequest::Base64(data) => data.as_ref().to_vec(),
        CommandContinuationRequest::Basic(_) => vec![],
    }
}

#[cfg(test)]
mod tests {
    use core::str;

    use alloc::format;

    use crate::sasl::auth_login::*;

    #[test]
    fn ir_success_returns_ok() {
        let opts = ImapAuthLoginOptions {
            initial_request: true,
            ..Default::default()
        };

        let mut auth = ImapAuthLogin::new("alice", "secret", opts);
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut auth, &mut frag, None);
        let line = str::from_utf8(&bytes).expect("utf8 command");
        let tag = first_word(line);
        assert!(line.contains("AUTHENTICATE LOGIN "));

        expect_wants_read(&mut auth, &mut frag);

        // NOTE: "Password:" base64 = "UGFzc3dvcmQ6".
        let pass = expect_wants_write(&mut auth, &mut frag, Some(b"+ UGFzc3dvcmQ6\r\n"));
        assert!(pass.ends_with(b"\r\n"));

        expect_wants_read(&mut auth, &mut frag);

        let reply = format!("{tag} OK AUTHENTICATE completed\r\n");
        expect_complete_ok(&mut auth, &mut frag, reply.as_bytes());
    }

    #[test]
    fn ir_invalid_password_returns_no_error() {
        let opts = ImapAuthLoginOptions {
            initial_request: true,
            ..Default::default()
        };

        let mut auth = ImapAuthLogin::new("alice", "wrong", opts);
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut auth, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command"));

        expect_wants_read(&mut auth, &mut frag);
        expect_wants_write(&mut auth, &mut frag, Some(b"+ UGFzc3dvcmQ6\r\n"));
        expect_wants_read(&mut auth, &mut frag);

        let reply = format!("{tag} NO authentication failed\r\n");
        let err = expect_complete_err(&mut auth, &mut frag, reply.as_bytes());
        let ImapAuthLoginError::No(text) = err else {
            panic!("expected ImapAuthLoginError::No, got {err:?}");
        };
        assert_eq!(text, "authentication failed");
    }

    #[test]
    fn ir_tagged_bad_returns_bad_error() {
        let opts = ImapAuthLoginOptions {
            initial_request: true,
            ..Default::default()
        };

        let mut auth = ImapAuthLogin::new("alice", "secret", opts);
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut auth, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command"));

        expect_wants_read(&mut auth, &mut frag);

        let reply = format!("{tag} BAD AUTHENTICATE not enabled\r\n");
        let err = expect_complete_err(&mut auth, &mut frag, reply.as_bytes());
        let ImapAuthLoginError::Bad(text) = err else {
            panic!("expected ImapAuthLoginError::Bad, got {err:?}");
        };
        assert_eq!(text, "AUTHENTICATE not enabled");
    }

    #[test]
    fn non_ir_success_returns_ok() {
        let opts = ImapAuthLoginOptions::default();
        let mut auth = ImapAuthLogin::new("alice", "secret", opts);
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut auth, &mut frag, None);
        let line = str::from_utf8(&bytes).expect("utf8 command");
        let tag = first_word(line);
        assert!(line.trim_end().ends_with("AUTHENTICATE LOGIN"));

        expect_wants_read(&mut auth, &mut frag);

        // NOTE: "Username:" base64 = "VXNlcm5hbWU6".
        let user = expect_wants_write(&mut auth, &mut frag, Some(b"+ VXNlcm5hbWU6\r\n"));
        assert!(user.ends_with(b"\r\n"));

        expect_wants_read(&mut auth, &mut frag);

        // NOTE: "Password:" base64 = "UGFzc3dvcmQ6".
        let pass = expect_wants_write(&mut auth, &mut frag, Some(b"+ UGFzc3dvcmQ6\r\n"));
        assert!(pass.ends_with(b"\r\n"));

        expect_wants_read(&mut auth, &mut frag);

        let reply = format!("{tag} OK AUTHENTICATE completed\r\n");
        expect_complete_ok(&mut auth, &mut frag, reply.as_bytes());
    }

    #[test]
    fn non_ir_invalid_password_returns_no_error() {
        let opts = ImapAuthLoginOptions::default();
        let mut auth = ImapAuthLogin::new("alice", "wrong", opts);
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut auth, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command"));

        expect_wants_read(&mut auth, &mut frag);
        expect_wants_write(&mut auth, &mut frag, Some(b"+ VXNlcm5hbWU6\r\n"));
        expect_wants_read(&mut auth, &mut frag);
        expect_wants_write(&mut auth, &mut frag, Some(b"+ UGFzc3dvcmQ6\r\n"));
        expect_wants_read(&mut auth, &mut frag);

        let reply = format!("{tag} NO authentication failed\r\n");
        let err = expect_complete_err(&mut auth, &mut frag, reply.as_bytes());
        let ImapAuthLoginError::No(text) = err else {
            panic!("expected ImapAuthLoginError::No, got {err:?}");
        };
        assert_eq!(text, "authentication failed");
    }

    #[test]
    fn ir_extra_prompt_returns_mechanism_error() {
        let opts = ImapAuthLoginOptions {
            initial_request: true,
            ..Default::default()
        };

        let mut auth = ImapAuthLogin::new("alice", "secret", opts);
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        expect_wants_write(&mut auth, &mut frag, None);
        expect_wants_read(&mut auth, &mut frag);
        expect_wants_write(&mut auth, &mut frag, Some(b"+ UGFzc3dvcmQ6\r\n"));
        expect_wants_read(&mut auth, &mut frag);

        // NOTE: a third prompt, which LOGIN has nothing left to answer.
        // The refusal is the mechanism's, this crate having no way to
        // know how many prompts a mechanism answers.
        let err = expect_complete_err(&mut auth, &mut frag, b"+ UGFzc3dvcmQ6\r\n");
        let ImapAuthLoginError::Mechanism(SaslLoginError::UnexpectedChallenge) = err else {
            panic!("expected ImapAuthLoginError::Mechanism, got {err:?}");
        };
    }

    fn expect_wants_write(
        cor: &mut ImapAuthLogin,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> Vec<u8> {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ImapAuthLogin, frag: &mut Fragmentizer) {
        match cor.resume(frag, None) {
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(cor: &mut ImapAuthLogin, frag: &mut Fragmentizer, reply: &[u8]) {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Complete(Ok(_)) => {}
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut ImapAuthLogin,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> ImapAuthLoginError {
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
}
