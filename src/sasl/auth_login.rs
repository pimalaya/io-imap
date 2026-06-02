//! I/O-free coroutine to authenticate an IMAP account via the SASL LOGIN
//! mechanism (legacy two-prompt mechanism, no RFC: pre-dates the IETF SASL
//! standardisation but is still widely deployed).  Both flows are supported:
//!
//! * non-IR ([`ImapAuthLogin::new`] with `initial_request: false`): bare
//!   `AUTHENTICATE LOGIN`, then the username and the password are each uploaded
//!   as continuation data after the server's `Username:` and `Password:`
//!   challenges.
//! * SASL-IR (RFC 4959, `initial_request: true`): the username is embedded
//!   inline as the initial response so only the password round-trip remains.

use core::mem;

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
use log::trace;
use thiserror::Error;

use crate::{coroutine::*, imap_try, rfc2971::id::*, rfc3501::capability::*, send::*};

/// Errors that can occur during LOGIN progression.
#[derive(Clone, Debug, Error)]
pub enum ImapAuthLoginError {
    #[error("Parse IMAP AUTHENTICATE NO error: {0}")]
    No(String),
    #[error("Parse IMAP AUTHENTICATE BAD error: {0}")]
    Bad(String),
    #[error("Parse IMAP AUTHENTICATE BYE error: {0}")]
    Bye(String),

    #[error("No IMAP AUTHENTICATE tagged response returned by the server")]
    MissingTagged,
    #[error("Parse IMAP AUTHENTICATE response: expected continuation request")]
    ExpectedContinuationRequest,
    #[error("Parse IMAP AUTHENTICATE LOGIN error: unexpected continuation request")]
    UnexpectedContinuationRequest,
    #[error("Parse IMAP AUTHENTICATE LOGIN error: expected continuation request got OK")]
    UnexpectedOk,

    #[error("Send IMAP AUTHENTICATE command error")]
    Send(#[from] SendImapCommandError),
    #[error(transparent)]
    Capability(#[from] ImapCapabilityGetError),
    #[error(transparent)]
    ServerId(#[from] ImapServerIdError),
}

/// Selects the LOGIN sub-flow and any post-authentication
/// round-trips.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImapAuthLoginOptions {
    /// When `true`, embed the username inline as the SASL initial
    /// response (RFC 4959); the coroutine starts in
    /// [`State::SendIr`]. When `false`, the username is uploaded as
    /// continuation data after the server's `Username:` challenge;
    /// the coroutine starts in [`State::Send`].
    pub initial_request: bool,
    pub ensure_capabilities: bool,
    pub auto_id: Option<Vec<(IString<'static>, NString<'static>)>>,
}

/// I/O-free SASL LOGIN coroutine. The initial [`State`] variant
/// ([`State::Send`] vs [`State::SendIr`]) selects between the non-IR
/// and SASL-IR flows.
pub struct ImapAuthLogin {
    state: State,
    password: String,
    observed: Vec<Capability<'static>>,
    opts: ImapAuthLoginOptions,
}

impl ImapAuthLogin {
    /// Creates a new LOGIN coroutine. `opts.initial_request` selects
    /// between the non-IR flow ([`State::Send`]) and the SASL-IR flow
    /// ([`State::SendIr`]).
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
            State::SendIr(SendImapCommand::new(CommandCodec::new(), cmd))
        } else {
            let body = CommandBody::Authenticate {
                mechanism: AuthMechanism::Login,
                initial_response: None,
            };
            let cmd = Command { tag, body };
            trace!("send IMAP command {cmd:?}");
            State::Send {
                send: SendImapCommand::new(CommandCodec::new(), cmd),
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
        Some(State::Id(ImapServerId::new(wire)))
    }

    fn next_continue_password(&mut self) -> State {
        let password = mem::take(&mut self.password).into_bytes();
        let auth = AuthenticateData::r#continue(password);
        let codec = AuthenticateDataCodec::new();
        State::ContinuePassword(SendImapCommand::new(codec, auth))
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
                        self.state = State::ContinueUsername(SendImapCommand::new(codec, auth));
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
                        continue;
                    }

                    if let Some(next) = self.wants_id() {
                        self.state = next;
                        continue;
                    }

                    let capability = mem::take(&mut self.observed);
                    return ImapCoroutineState::Complete(Ok(capability));
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
        user: String,
    },
    SendIr(SendImapCommand<CommandCodec>),
    ContinueUsername(SendImapCommand<AuthenticateDataCodec>),
    ContinuePassword(SendImapCommand<AuthenticateDataCodec>),
    Capability(ImapCapabilityGet),
    Id(ImapServerId),
}

#[cfg(test)]
mod tests {
    use core::str;

    use super::*;

    /// SASL-IR happy path: username embedded inline, only the password
    /// continuation round-trip remains, server returns tagged OK.
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

        // "Password:" base64 = "UGFzc3dvcmQ6".
        let pass = expect_wants_write(&mut auth, &mut frag, Some(b"+ UGFzc3dvcmQ6\r\n"));
        assert!(pass.ends_with(b"\r\n"));

        expect_wants_read(&mut auth, &mut frag);

        let reply = format!("{tag} OK AUTHENTICATE completed\r\n");
        expect_complete_ok(&mut auth, &mut frag, reply.as_bytes());
    }

    /// SASL-IR error path: server accepts the username but rejects the
    /// password with tagged NO.
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

    /// Tagged BAD before any continuation: surface text verbatim.
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

    /// Non-IR happy path: client sends bare AUTHENTICATE, server walks
    /// the client through `Username:` then `Password:` continuations,
    /// returns tagged OK.
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

        // "Username:" base64 = "VXNlcm5hbWU6".
        let user = expect_wants_write(&mut auth, &mut frag, Some(b"+ VXNlcm5hbWU6\r\n"));
        assert!(user.ends_with(b"\r\n"));

        expect_wants_read(&mut auth, &mut frag);

        // "Password:" base64 = "UGFzc3dvcmQ6".
        let pass = expect_wants_write(&mut auth, &mut frag, Some(b"+ UGFzc3dvcmQ6\r\n"));
        assert!(pass.ends_with(b"\r\n"));

        expect_wants_read(&mut auth, &mut frag);

        let reply = format!("{tag} OK AUTHENTICATE completed\r\n");
        expect_complete_ok(&mut auth, &mut frag, reply.as_bytes());
    }

    /// Non-IR error path: both username and password upload, server
    /// returns tagged NO at the end.
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

    // --- utils

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
