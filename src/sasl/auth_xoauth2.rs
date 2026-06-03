//! IMAP SASL XOAUTH2 coroutine (Google's pre-standard OAuth 2.0
//! mechanism, also accepted by Microsoft Exchange Online); supports
//! both the non-IR and SASL-IR (RFC 4959) flows.
//!
//! XOAUTH2: <https://developers.google.com/workspace/gmail/imap/xoauth2-protocol>
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
//!     sasl::auth_xoauth2::{ImapAuthXoauth2, ImapAuthXoauth2Options},
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negociated)
//! let mut stream = TcpStream::connect("localhost:143").unwrap();
//!
//! let mut fragmentizer = Fragmentizer::new(50 * 1024 * 1024);
//! let mut buf = [0u8; 4096];
//!
//! let opts = ImapAuthXoauth2Options::default();
//! let mut coroutine = ImapAuthXoauth2::new("alice@example.org", "oauth-token", opts);
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

/// Failure causes during the SASL XOAUTH2 flow.
#[derive(Clone, Debug, Error)]
pub enum ImapAuthXoauth2Error {
    #[error("IMAP AUTHENTICATE XOAUTH2 failed: NO {0}")]
    No(String),
    #[error("IMAP AUTHENTICATE XOAUTH2 failed: NO {info} ({err})")]
    NoWithError { info: String, err: String },
    #[error("IMAP AUTHENTICATE XOAUTH2 failed: BAD {0}")]
    Bad(String),
    #[error("IMAP AUTHENTICATE XOAUTH2 failed: BYE {0}")]
    Bye(String),

    #[error("IMAP AUTHENTICATE XOAUTH2 failed: server did not return a tagged response")]
    MissingTagged,
    #[error(
        "IMAP AUTHENTICATE XOAUTH2 failed: server did not send the expected continuation request"
    )]
    ExpectedContinuationRequest,
    #[error("IMAP AUTHENTICATE XOAUTH2 failed: expected NO got {kind:?} ({info})")]
    UnexpectedStatus { kind: StatusKind, info: String },
    #[error(
        "IMAP AUTHENTICATE XOAUTH2 failed: server returned OK before the mechanism could complete"
    )]
    UnexpectedOk,

    #[error("IMAP AUTHENTICATE XOAUTH2 failed: {0}")]
    Send(#[from] SendImapCommandError),
    #[error(transparent)]
    Capability(#[from] ImapCapabilityGetError),
    #[error(transparent)]
    ServerId(#[from] ImapServerIdError),
}

/// Options for [`ImapAuthXoauth2::new`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImapAuthXoauth2Options {
    /// `true` selects SASL-IR (RFC 4959, inline credentials);
    /// `false` selects the non-IR upload-after-challenge flow.
    pub initial_request: bool,
    pub ensure_capabilities: bool,
    pub auto_id: Option<Vec<(IString<'static>, NString<'static>)>>,
}

/// I/O-free SASL XOAUTH2 coroutine.
pub struct ImapAuthXoauth2 {
    state: State,
    error: Option<String>,
    observed: Vec<Capability<'static>>,
    opts: ImapAuthXoauth2Options,
}

impl ImapAuthXoauth2 {
    pub fn new(
        user: impl AsRef<str>,
        token: impl AsRef<str>,
        opts: ImapAuthXoauth2Options,
    ) -> Self {
        let user = user.as_ref();
        let token = token.as_ref();
        let payload = format!("user={user}\x01auth=Bearer {token}\x01\x01");
        let payload = Cow::from(payload.into_bytes());
        let tag = TagGenerator::new().generate();

        let state = if opts.initial_request {
            let body = CommandBody::Authenticate {
                mechanism: AuthMechanism::XOAuth2,
                initial_response: Some(Secret::new(payload)),
            };
            let cmd = Command { tag, body };
            trace!("send IMAP command {cmd:?}");
            State::SendIr(SendImapCommand::new(CommandCodec::new(), cmd))
        } else {
            let body = CommandBody::Authenticate {
                mechanism: AuthMechanism::XOAuth2,
                initial_response: None,
            };
            let cmd = Command { tag, body };
            trace!("send IMAP command {cmd:?}");
            let send = SendImapCommand::new(CommandCodec::new(), cmd);
            State::Send { send, payload }
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

impl ImapCoroutine for ImapAuthXoauth2 {
    type Yield = ImapYield;
    type Return = Result<Vec<Capability<'static>>, ImapAuthXoauth2Error>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        loop {
            trace!("auth XOAUTH2: {}", self.state);
            match &mut self.state {
                State::Send { send, payload } => {
                    let out = imap_try!(send, fragmentizer, arg);

                    if let Some(bye) = out.bye {
                        let err = ImapAuthXoauth2Error::Bye(bye.text.to_string());
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
                            StatusKind::Ok => ImapAuthXoauth2Error::UnexpectedOk,
                            StatusKind::No => ImapAuthXoauth2Error::No(body.text.to_string()),
                            StatusKind::Bad => ImapAuthXoauth2Error::Bad(body.text.to_string()),
                        };

                        return ImapCoroutineState::Complete(Err(err));
                    }

                    let err = ImapAuthXoauth2Error::ExpectedContinuationRequest;
                    return ImapCoroutineState::Complete(Err(err));
                }
                State::SendIr(send) => {
                    let out = imap_try!(send, fragmentizer, arg);

                    if let Some(bye) = out.bye {
                        let err = ImapAuthXoauth2Error::Bye(bye.text.to_string());
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    if let Some(cr) = out.continuation_request {
                        self.error.replace(Self::extract_json_error(&cr));
                        let auth = AuthenticateData::r#continue(vec![]);
                        let codec = AuthenticateDataCodec::new();
                        self.state = State::AcknowledgeError(SendImapCommand::new(codec, auth));
                        continue;
                    }

                    let Some(Tagged { body, .. }) = out.tagged else {
                        let err = ImapAuthXoauth2Error::MissingTagged;
                        return ImapCoroutineState::Complete(Err(err));
                    };

                    let code = match body.kind {
                        StatusKind::Ok => body.code,
                        StatusKind::No => {
                            let err = ImapAuthXoauth2Error::No(body.text.to_string());
                            return ImapCoroutineState::Complete(Err(err));
                        }
                        StatusKind::Bad => {
                            let err = ImapAuthXoauth2Error::Bad(body.text.to_string());
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
                        let err = ImapAuthXoauth2Error::Bye(bye.text.to_string());
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    if let Some(cr) = out.continuation_request {
                        self.error.replace(Self::extract_json_error(&cr));
                        let auth = AuthenticateData::r#continue(vec![]);
                        let codec = AuthenticateDataCodec::new();
                        self.state = State::AcknowledgeError(SendImapCommand::new(codec, auth));
                        continue;
                    }

                    let Some(Tagged { body, .. }) = out.tagged else {
                        let err = ImapAuthXoauth2Error::MissingTagged;
                        return ImapCoroutineState::Complete(Err(err));
                    };

                    let code = match body.kind {
                        StatusKind::Ok => body.code,
                        StatusKind::No => {
                            let err = ImapAuthXoauth2Error::No(body.text.to_string());
                            return ImapCoroutineState::Complete(Err(err));
                        }
                        StatusKind::Bad => {
                            let err = ImapAuthXoauth2Error::Bad(body.text.to_string());
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
                        let err = ImapAuthXoauth2Error::Bye(bye.text.to_string());
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    let Some(Tagged { body, .. }) = out.tagged else {
                        let err = ImapAuthXoauth2Error::MissingTagged;
                        return ImapCoroutineState::Complete(Err(err));
                    };

                    let info = body.text.to_string();

                    let StatusKind::No = body.kind else {
                        let kind = body.kind;
                        let err = ImapAuthXoauth2Error::UnexpectedStatus { kind, info };
                        return ImapCoroutineState::Complete(Err(err));
                    };

                    let err = match self.error.take() {
                        Some(err) => ImapAuthXoauth2Error::NoWithError { info, err },
                        None => ImapAuthXoauth2Error::No(info),
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
        let opts = ImapAuthXoauth2Options {
            initial_request: true,
            ..Default::default()
        };

        let mut auth = ImapAuthXoauth2::new("user@example.org", "oauth-token", opts);
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut auth, &mut frag, None);
        let line = str::from_utf8(&bytes).expect("utf8 command");
        let tag = first_word(line);
        assert!(line.contains("AUTHENTICATE XOAUTH2 "));

        expect_wants_read(&mut auth, &mut frag);

        let reply = format!("{tag} OK AUTHENTICATE completed\r\n");
        expect_complete_ok(&mut auth, &mut frag, reply.as_bytes());
    }

    #[test]
    fn ir_invalid_token_returns_no_with_error() {
        let opts = ImapAuthXoauth2Options {
            initial_request: true,
            ..Default::default()
        };

        let mut auth = ImapAuthXoauth2::new("user@example.org", "expired-token", opts);
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut auth, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command"));

        expect_wants_read(&mut auth, &mut frag);

        let (err_json_b64, err_json) = fake_json_error();
        let challenge = format!("+ {err_json_b64}\r\n");
        let ack = expect_wants_write(&mut auth, &mut frag, Some(challenge.as_bytes()));
        assert_eq!(b"\r\n", &*ack);

        expect_wants_read(&mut auth, &mut frag);

        let reply = format!("{tag} NO SASL authentication failed\r\n");
        let err = expect_complete_err(&mut auth, &mut frag, reply.as_bytes());
        let ImapAuthXoauth2Error::NoWithError { info, err } = err else {
            panic!("expected ImapAuthXoauth2Error::NoWithError, got {err:?}");
        };
        assert_eq!(info, "SASL authentication failed");
        assert_eq!(err, err_json);
    }

    #[test]
    fn ir_tagged_bad_returns_bad_error() {
        let opts = ImapAuthXoauth2Options {
            initial_request: true,
            ..Default::default()
        };

        let mut auth = ImapAuthXoauth2::new("user@example.org", "oauth-token", opts);
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut auth, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command"));

        expect_wants_read(&mut auth, &mut frag);

        let reply = format!("{tag} BAD AUTHENTICATE not enabled\r\n");
        let err = expect_complete_err(&mut auth, &mut frag, reply.as_bytes());
        let ImapAuthXoauth2Error::Bad(text) = err else {
            panic!("expected ImapAuthXoauth2Error::NoWithError, got {err:?}");
        };
        assert_eq!(text, "AUTHENTICATE not enabled");
    }

    #[test]
    fn non_ir_success_returns_ok() {
        let opts = ImapAuthXoauth2Options::default();
        let mut auth = ImapAuthXoauth2::new("user@example.org", "oauth-token", opts);
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut auth, &mut frag, None);
        let line = str::from_utf8(&bytes).expect("utf8 command");
        let tag = first_word(line);
        assert!(line.trim_end().ends_with("AUTHENTICATE XOAUTH2"));

        expect_wants_read(&mut auth, &mut frag);

        let creds = expect_wants_write(&mut auth, &mut frag, Some(b"+ \r\n"));
        assert!(creds.ends_with(b"\r\n"));

        expect_wants_read(&mut auth, &mut frag);

        let reply = format!("{tag} OK AUTHENTICATE completed\r\n");
        expect_complete_ok(&mut auth, &mut frag, reply.as_bytes());
    }

    #[test]
    fn non_ir_invalid_token_returns_no_with_error() {
        let opts = ImapAuthXoauth2Options::default();
        let mut auth = ImapAuthXoauth2::new("user@example.org", "expired-token", opts);
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut auth, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command"));

        expect_wants_read(&mut auth, &mut frag);
        expect_wants_write(&mut auth, &mut frag, Some(b"+ \r\n"));
        expect_wants_read(&mut auth, &mut frag);

        let (err_json_b64, err_json) = fake_json_error();
        let challenge = format!("+ {err_json_b64}\r\n");
        let ack = expect_wants_write(&mut auth, &mut frag, Some(challenge.as_bytes()));
        assert_eq!(b"\r\n", &*ack);

        expect_wants_read(&mut auth, &mut frag);

        let reply = format!("{tag} NO SASL authentication failed\r\n");
        let err = expect_complete_err(&mut auth, &mut frag, reply.as_bytes());
        let ImapAuthXoauth2Error::NoWithError { info, err } = err else {
            panic!("expected ImapAuthXoauth2Error::NoWithError, got {err:?}");
        };
        assert_eq!(info, "SASL authentication failed");
        assert_eq!(err, err_json);
    }

    // --- utils

    fn expect_wants_write(
        cor: &mut ImapAuthXoauth2,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> Vec<u8> {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ImapAuthXoauth2, frag: &mut Fragmentizer) {
        match cor.resume(frag, None) {
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(cor: &mut ImapAuthXoauth2, frag: &mut Fragmentizer, reply: &[u8]) {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Complete(Ok(_)) => {}
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut ImapAuthXoauth2,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> ImapAuthXoauth2Error {
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
            "eyJzdGF0dXMiOiI0MDEiLCJzY2hlbWVzIjoiQmVhcmVyIiwic2NvcGUiOiJodHRwczovL21haWwuZ29vZ2xlLmNvbS8ifQ==",
            "{\"status\":\"401\",\"schemes\":\"Bearer\",\"scope\":\"https://mail.google.com/\"}",
        )
    }
}
