//! IMAP SASL OAUTHBEARER coroutine; supports both the non-IR and
//! SASL-IR (RFC 4959) flows.
//!
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
//!     rfc7628::auth_oauthbearer::{ImapAuthOauthbearer, ImapAuthOauthbearerOptions},
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negociated)
//! let mut stream = TcpStream::connect("localhost:143").unwrap();
//!
//! let mut fragmentizer = Fragmentizer::new(50 * 1024 * 1024);
//! let mut buf = [0u8; 4096];
//!
//! let opts = ImapAuthOauthbearerOptions::default();
//! let mut coroutine = ImapAuthOauthbearer::new(
//!     "alice@example.org",
//!     "imap.example.org",
//!     993,
//!     "oauth-token",
//!     opts,
//! );
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
    borrow::Cow,
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
use log::trace;
use thiserror::Error;

use crate::{coroutine::*, imap_try, rfc2971::id::*, rfc3501::capability::*, send::*};

/// Failure causes during the SASL OAUTHBEARER flow.
#[derive(Clone, Debug, Error)]
pub enum ImapAuthOauthbearerError {
    #[error("IMAP AUTHENTICATE OAUTHBEARER failed: NO {0}")]
    No(String),
    #[error("IMAP AUTHENTICATE OAUTHBEARER failed: NO {info} ({err})")]
    NoWithError { info: String, err: String },
    #[error("IMAP AUTHENTICATE OAUTHBEARER failed: BAD {0}")]
    Bad(String),
    #[error("IMAP AUTHENTICATE OAUTHBEARER failed: BYE {0}")]
    Bye(String),

    #[error("IMAP AUTHENTICATE OAUTHBEARER failed: server did not return a tagged response")]
    MissingTagged,
    #[error(
        "IMAP AUTHENTICATE OAUTHBEARER failed: server did not send the expected continuation request"
    )]
    ExpectedContinuationRequest,
    #[error("IMAP AUTHENTICATE OAUTHBEARER failed: expected NO got {kind:?} ({info})")]
    UnexpectedStatus { kind: StatusKind, info: String },
    #[error(
        "IMAP AUTHENTICATE OAUTHBEARER failed: server returned OK before the mechanism could complete"
    )]
    UnexpectedOk,

    #[error("IMAP AUTHENTICATE OAUTHBEARER failed: {0}")]
    Send(#[from] SendImapCommandError),
    #[error(transparent)]
    Capability(#[from] ImapCapabilityGetError),
    #[error(transparent)]
    ServerId(#[from] ImapServerIdError),
}

/// Options for [`ImapAuthOauthbearer::new`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImapAuthOauthbearerOptions {
    /// `true` selects SASL-IR (RFC 4959, inline credentials);
    /// `false` selects the non-IR upload-after-challenge flow.
    pub initial_request: bool,
    pub ensure_capabilities: bool,
    pub auto_id: Option<Vec<(IString<'static>, NString<'static>)>>,
}

/// I/O-free SASL OAUTHBEARER coroutine.
pub struct ImapAuthOauthbearer {
    state: State,
    error: Option<String>,
    observed: Vec<Capability<'static>>,
    opts: ImapAuthOauthbearerOptions,
}

impl ImapAuthOauthbearer {
    pub fn new(
        user: impl AsRef<str>,
        host: impl AsRef<str>,
        port: u16,
        token: impl AsRef<str>,
        opts: ImapAuthOauthbearerOptions,
    ) -> Self {
        let tag = TagGenerator::new().generate();

        let u = user.as_ref();
        let h = host.as_ref();
        let t = token.as_ref();

        let payload = format!("n,a={u},\x01host={h}\x01port={port}\x01auth=Bearer {t}\x01\x01");
        let payload = payload.into_bytes().into();

        let state = if opts.initial_request {
            let body = CommandBody::Authenticate {
                mechanism: AuthMechanism::OAuthBearer,
                initial_response: Some(Secret::new(payload)),
            };
            let cmd = Command { tag, body };
            trace!("send IMAP command {cmd:?}");
            State::SendIr(SendImapCommand::new(CommandCodec::new(), cmd))
        } else {
            let body = CommandBody::Authenticate {
                mechanism: AuthMechanism::OAuthBearer,
                initial_response: None,
            };
            let cmd = Command { tag, body };
            trace!("send IMAP command {cmd:?}");
            let send = SendImapCommand::new(CommandCodec::new(), cmd);
            State::Send { payload, send }
        };

        Self {
            state,
            error: None,
            observed: Vec::new(),
            opts,
        }
    }

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

    fn wants_id(&mut self) -> Option<State> {
        let params = self.opts.auto_id.take()?;
        let wire = (!params.is_empty()).then_some(params);
        Some(State::Id(ImapServerId::new(ImapServerIdOptions {
            parameters: wire,
        })))
    }

    fn extract_json_error(cr: &CommandContinuationRequest<'_>) -> String {
        let err = match cr {
            CommandContinuationRequest::Basic(err) => err.text().to_string().into(),
            CommandContinuationRequest::Base64(err) => String::from_utf8_lossy(err),
        };

        err.to_string()
    }
}

impl ImapCoroutine for ImapAuthOauthbearer {
    type Yield = ImapYield;
    type Return = Result<Vec<Capability<'static>>, ImapAuthOauthbearerError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        loop {
            trace!("auth OAUTHBEARER: {}", self.state);
            match &mut self.state {
                State::Send { send, payload } => {
                    let out = imap_try!(send, fragmentizer, arg);

                    if let Some(bye) = out.bye {
                        let err = ImapAuthOauthbearerError::Bye(bye.text.to_string());
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    if out.continuation_request.is_some() {
                        let payload = mem::take(payload).into_owned();
                        let auth = AuthenticateData::r#continue(payload);
                        let codec = AuthenticateDataCodec::new();
                        self.state = State::Continue(SendImapCommand::new(codec, auth));
                        continue;
                    }

                    if let Some(Tagged { body, .. }) = out.tagged {
                        let err = match body.kind {
                            StatusKind::Ok => ImapAuthOauthbearerError::UnexpectedOk,
                            StatusKind::No => ImapAuthOauthbearerError::No(body.text.to_string()),
                            StatusKind::Bad => ImapAuthOauthbearerError::Bad(body.text.to_string()),
                        };

                        return ImapCoroutineState::Complete(Err(err));
                    }

                    let err = ImapAuthOauthbearerError::ExpectedContinuationRequest;
                    return ImapCoroutineState::Complete(Err(err));
                }
                State::SendIr(send) => {
                    let out = imap_try!(send, fragmentizer, arg);

                    if let Some(bye) = out.bye {
                        let err = ImapAuthOauthbearerError::Bye(bye.text.to_string());
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    if let Some(cr) = out.continuation_request {
                        self.error.replace(Self::extract_json_error(&cr));
                        let auth = AuthenticateData::r#continue(vec![0x01]);
                        let codec = AuthenticateDataCodec::new();
                        self.state = State::AcknowledgeError(SendImapCommand::new(codec, auth));
                        continue;
                    }

                    let Some(Tagged { body, .. }) = out.tagged else {
                        let err = ImapAuthOauthbearerError::MissingTagged;
                        return ImapCoroutineState::Complete(Err(err));
                    };

                    let code = match body.kind {
                        StatusKind::Ok => body.code,
                        StatusKind::No => {
                            let err = ImapAuthOauthbearerError::No(body.text.to_string());
                            return ImapCoroutineState::Complete(Err(err));
                        }
                        StatusKind::Bad => {
                            let err = ImapAuthOauthbearerError::Bad(body.text.to_string());
                            return ImapCoroutineState::Complete(Err(err));
                        }
                    };

                    if let Some(next) = self.wants_capability(code, out.data, out.untagged) {
                        self.state = next;
                        continue;
                    }

                    if let Some(next) = self.wants_id() {
                        self.state = next;
                        continue;
                    }

                    let capability = mem::take(&mut self.observed);
                    return ImapCoroutineState::Complete(Ok(capability));
                }
                State::Continue(send) => {
                    let out = imap_try!(send, fragmentizer, arg);

                    if let Some(bye) = out.bye {
                        let err = ImapAuthOauthbearerError::Bye(bye.text.to_string());
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    if let Some(cr) = out.continuation_request {
                        self.error.replace(Self::extract_json_error(&cr));
                        let auth = AuthenticateData::r#continue(vec![0x01]);
                        let codec = AuthenticateDataCodec::new();
                        self.state = State::AcknowledgeError(SendImapCommand::new(codec, auth));
                        continue;
                    }

                    let Some(Tagged { body, .. }) = out.tagged else {
                        let err = ImapAuthOauthbearerError::MissingTagged;
                        return ImapCoroutineState::Complete(Err(err));
                    };

                    let code = match body.kind {
                        StatusKind::Ok => body.code,
                        StatusKind::No => {
                            let err = ImapAuthOauthbearerError::No(body.text.to_string());
                            return ImapCoroutineState::Complete(Err(err));
                        }
                        StatusKind::Bad => {
                            let err = ImapAuthOauthbearerError::Bad(body.text.to_string());
                            return ImapCoroutineState::Complete(Err(err));
                        }
                    };

                    if let Some(next) = self.wants_capability(code, out.data, out.untagged) {
                        self.state = next;
                        continue;
                    }

                    if let Some(next) = self.wants_id() {
                        self.state = next;
                        continue;
                    }

                    let capability = mem::take(&mut self.observed);
                    return ImapCoroutineState::Complete(Ok(capability));
                }
                State::AcknowledgeError(send) => {
                    let out = imap_try!(send, fragmentizer, arg);

                    if let Some(bye) = out.bye {
                        let err = ImapAuthOauthbearerError::Bye(bye.text.to_string());
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    let Some(Tagged { body, .. }) = out.tagged else {
                        let err = ImapAuthOauthbearerError::MissingTagged;
                        return ImapCoroutineState::Complete(Err(err));
                    };

                    let info = body.text.to_string();

                    let StatusKind::No = body.kind else {
                        let kind = body.kind;
                        let err = ImapAuthOauthbearerError::UnexpectedStatus { kind, info };
                        return ImapCoroutineState::Complete(Err(err));
                    };

                    let err = match self.error.take() {
                        Some(err) => ImapAuthOauthbearerError::NoWithError { info, err },
                        None => ImapAuthOauthbearerError::No(info),
                    };

                    return ImapCoroutineState::Complete(Err(err));
                }
                State::Capability(capability) => {
                    self.observed = imap_try!(capability, fragmentizer, arg);

                    if let Some(next) = self.wants_id() {
                        self.state = next;
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
    Send {
        send: SendImapCommand<CommandCodec>,
        payload: Cow<'static, [u8]>,
    },
    SendIr(SendImapCommand<CommandCodec>),
    Continue(SendImapCommand<AuthenticateDataCodec>),
    AcknowledgeError(SendImapCommand<AuthenticateDataCodec>),
    Capability(ImapCapabilityGet),
    Id(ImapServerId),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send { .. } => f.write_str("send auth"),
            Self::SendIr(_) => f.write_str("send auth with ir"),
            Self::Continue(_) => f.write_str("send credentials"),
            Self::AcknowledgeError(_) => f.write_str("acknowledge error"),
            Self::Capability(_) => f.write_str("fetch capabilities"),
            Self::Id(_) => f.write_str("send id"),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::str;

    use super::*;

    #[test]
    fn ir_success_returns_ok() {
        let opts = ImapAuthOauthbearerOptions {
            initial_request: true,
            ..Default::default()
        };

        let mut auth = ImapAuthOauthbearer::new(
            "user@example.org",
            "imap.example.org",
            993,
            "oauth-token",
            opts,
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut auth, &mut frag, None);
        let line = str::from_utf8(&bytes).expect("utf8 command");
        let tag = first_word(line);
        assert!(line.contains("AUTHENTICATE OAUTHBEARER "));

        expect_wants_read(&mut auth, &mut frag);

        let reply = format!("{tag} OK AUTHENTICATE completed\r\n");
        expect_complete_ok(&mut auth, &mut frag, reply.as_bytes());
    }

    #[test]
    fn ir_invalid_token_returns_no_with_error() {
        let opts = ImapAuthOauthbearerOptions {
            initial_request: true,
            ..Default::default()
        };

        let mut auth = ImapAuthOauthbearer::new(
            "user@example.org",
            "imap.example.org",
            993,
            "expired-token",
            opts,
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut auth, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command"));

        expect_wants_read(&mut auth, &mut frag);

        let (err_json_b64, err_json) = fake_json_error();
        let challenge = format!("+ {err_json_b64}\r\n");
        let ack = expect_wants_write(&mut auth, &mut frag, Some(challenge.as_bytes()));
        assert_eq!(b"AQ==\r\n", &*ack);

        expect_wants_read(&mut auth, &mut frag);

        let reply = format!("{tag} NO SASL authentication failed\r\n");
        let err = expect_complete_err(&mut auth, &mut frag, reply.as_bytes());
        let ImapAuthOauthbearerError::NoWithError { info, err } = err else {
            panic!("expected ImapAuthOauthbearerError::NoWithError, got {err:?}");
        };
        assert_eq!(info, "SASL authentication failed");
        assert_eq!(err, err_json);
    }

    #[test]
    fn ir_tagged_bad_returns_bad_error() {
        let opts = ImapAuthOauthbearerOptions {
            initial_request: true,
            ..Default::default()
        };

        let mut auth = ImapAuthOauthbearer::new(
            "user@example.org",
            "imap.example.org",
            993,
            "oauth-token",
            opts,
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut auth, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command"));

        expect_wants_read(&mut auth, &mut frag);

        let reply = format!("{tag} BAD AUTHENTICATE not enabled\r\n");
        let err = expect_complete_err(&mut auth, &mut frag, reply.as_bytes());
        let ImapAuthOauthbearerError::Bad(text) = err else {
            panic!("expected ImapAuthOauthbearerError::Bad, got {err:?}");
        };
        assert_eq!(text, "AUTHENTICATE not enabled");
    }

    #[test]
    fn non_ir_success_returns_ok() {
        let opts = ImapAuthOauthbearerOptions::default();
        let mut auth = ImapAuthOauthbearer::new(
            "user@example.org",
            "imap.example.org",
            993,
            "oauth-token",
            opts,
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut auth, &mut frag, None);
        let line = str::from_utf8(&bytes).expect("utf8 command");
        let tag = first_word(line);
        assert!(line.trim_end().ends_with("AUTHENTICATE OAUTHBEARER"));

        expect_wants_read(&mut auth, &mut frag);

        let creds = expect_wants_write(&mut auth, &mut frag, Some(b"+ \r\n"));
        assert!(creds.ends_with(b"\r\n"));

        expect_wants_read(&mut auth, &mut frag);

        let reply = format!("{tag} OK AUTHENTICATE completed\r\n");
        expect_complete_ok(&mut auth, &mut frag, reply.as_bytes());
    }

    #[test]
    fn non_ir_invalid_token_returns_no_with_error() {
        let opts = ImapAuthOauthbearerOptions::default();
        let mut auth = ImapAuthOauthbearer::new(
            "user@example.org",
            "imap.example.org",
            993,
            "expired-token",
            opts,
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut auth, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command"));

        expect_wants_read(&mut auth, &mut frag);
        expect_wants_write(&mut auth, &mut frag, Some(b"+ \r\n"));
        expect_wants_read(&mut auth, &mut frag);

        let (err_json_b64, err_json) = fake_json_error();
        let challenge = format!("+ {err_json_b64}\r\n");
        let ack = expect_wants_write(&mut auth, &mut frag, Some(challenge.as_bytes()));
        assert_eq!(b"AQ==\r\n", &*ack);

        expect_wants_read(&mut auth, &mut frag);

        let reply = format!("{tag} NO SASL authentication failed\r\n");
        let err = expect_complete_err(&mut auth, &mut frag, reply.as_bytes());
        let ImapAuthOauthbearerError::NoWithError { info, err } = err else {
            panic!("expected ImapAuthOauthbearerError::NoWithError, got {err:?}");
        };
        assert_eq!(info, "SASL authentication failed");
        assert_eq!(err, err_json);
    }

    // --- utils

    fn expect_wants_write(
        cor: &mut ImapAuthOauthbearer,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> Vec<u8> {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ImapAuthOauthbearer, frag: &mut Fragmentizer) {
        match cor.resume(frag, None) {
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(cor: &mut ImapAuthOauthbearer, frag: &mut Fragmentizer, reply: &[u8]) {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Complete(Ok(_)) => {}
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut ImapAuthOauthbearer,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> ImapAuthOauthbearerError {
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

    fn fake_json_error() -> (&'static str, &'static str) {
        (
            "eyJzdGF0dXMiOiJpbnZhbGlkX3Rva2VuIiwic2NvcGUiOiJleGFtcGxlX3Njb3BlIiwib3BlbmlkLWNvbmZpZ3VyYXRpb24iOiJodHRwczovL2V4YW1wbGUuY29tLy53ZWxsLWtub3duL29wZW5pZC1jb25maWd1cmF0aW9uIn0=",
            "{\"status\":\"invalid_token\",\"scope\":\"example_scope\",\"openid-configuration\":\"https://example.com/.well-known/openid-configuration\"}",
        )
    }
}
