//! IMAP SASL LOGIN coroutine (legacy two-prompt mechanism, pre-IETF);
//! supports both the non-IR and SASL-IR (RFC 4959) flows.
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
    vec::Vec,
};

use imap_codec::{
    AuthenticateDataCodec, CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        auth::{AuthMechanism, AuthenticateData},
        command::{Command, CommandBody},
        core::{IString, NString, TagGenerator},
        response::{Capability, Code, Data, StatusBody, StatusKind, Tagged},
        secret::Secret,
    },
};
use log::{debug, trace};
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
    /// The server sent a continuation request after the exchange ended.
    #[error("IMAP AUTHENTICATE LOGIN failed: server sent an unexpected continuation request")]
    UnexpectedContinuationRequest,
    /// The server returned OK before the mechanism could complete.
    #[error(
        "IMAP AUTHENTICATE LOGIN failed: server returned OK before the mechanism could complete"
    )]
    UnexpectedOk,
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
    password: String,
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
        let user = user.as_ref();
        let password = password.as_ref().to_string();
        let tag = TagGenerator::new().generate();

        let state = if opts.initial_request {
            let body = CommandBody::Authenticate {
                mechanism: AuthMechanism::Login,
                initial_response: Some(Secret::new(user.as_bytes().to_vec().into())),
            };
            let cmd = Command { tag, body };
            trace!("send IMAP command {cmd:?}");
            State::SendIr(ImapSend::new(CommandCodec::new(), cmd))
        } else {
            let body = CommandBody::Authenticate {
                mechanism: AuthMechanism::Login,
                initial_response: None,
            };
            let cmd = Command { tag, body };
            trace!("send IMAP command {cmd:?}");
            State::Send {
                send: ImapSend::new(CommandCodec::new(), cmd),
                user: user.to_string(),
            }
        };

        Self {
            state,
            password,
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

    fn next_continue_password(&mut self) -> State {
        let password = mem::take(&mut self.password).into_bytes();
        let auth = AuthenticateData::r#continue(password);
        let codec = AuthenticateDataCodec::new();
        State::ContinuePassword(ImapSend::new(codec, auth))
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
                State::Send { send, user } => {
                    let out = imap_try!(send, fragmentizer, arg);

                    if let Some(bye) = out.bye {
                        let err = ImapAuthLoginError::Bye(bye.text.to_string());
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    if out.continuation_request.is_some() {
                        let user = mem::take(user).into_bytes();
                        let auth = AuthenticateData::r#continue(user);
                        let codec = AuthenticateDataCodec::new();
                        self.state = State::ContinueUsername(ImapSend::new(codec, auth));
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
                State::SendIr(send) => {
                    let out = imap_try!(send, fragmentizer, arg);

                    if let Some(bye) = out.bye {
                        let err = ImapAuthLoginError::Bye(bye.text.to_string());
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    if out.continuation_request.is_some() {
                        self.state = self.next_continue_password();
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
                State::ContinueUsername(send) => {
                    let out = imap_try!(send, fragmentizer, arg);

                    if let Some(bye) = out.bye {
                        let err = ImapAuthLoginError::Bye(bye.text.to_string());
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    if out.continuation_request.is_some() {
                        self.state = self.next_continue_password();
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
                State::ContinuePassword(send) => {
                    let out = imap_try!(send, fragmentizer, arg);

                    if let Some(bye) = out.bye {
                        let err = ImapAuthLoginError::Bye(bye.text.to_string());
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    if out.continuation_request.is_some() {
                        let err = ImapAuthLoginError::UnexpectedContinuationRequest;
                        return ImapCoroutineState::Complete(Err(err));
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
    Send {
        send: ImapSend<CommandCodec>,
        user: String,
    },
    SendIr(ImapSend<CommandCodec>),
    ContinueUsername(ImapSend<AuthenticateDataCodec>),
    ContinuePassword(ImapSend<AuthenticateDataCodec>),
    Capability(ImapCapabilityGet),
    Id(ImapServerId),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send { .. } => f.write_str("send auth"),
            Self::SendIr(_) => f.write_str("send auth with ir"),
            Self::ContinueUsername(_) => f.write_str("send username"),
            Self::ContinuePassword(_) => f.write_str("send password"),
            Self::Capability(_) => f.write_str("fetch capabilities"),
            Self::Id(_) => f.write_str("send id"),
        }
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
