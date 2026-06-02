//! I/O-free coroutine to authenticate an IMAP account via SASL PLAIN (RFC
//! 4616). Both flows are supported:
//!
//! * non-IR ([`ImapAuthPlain::new`] with `initial_request: false`): bare
//!   `AUTHENTICATE PLAIN`, then the credentials are uploaded as continuation
//!   data after the server's empty SASL challenge.
//! * SASL-IR (RFC 4959, `initial_request: true`): credentials embedded inline
//!   as the initial response so the auth completes in a single round-trip on
//!   success.

use core::mem;

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
        response::{Capability, Code, Data, StatusBody, StatusKind, Tagged},
        secret::Secret,
    },
};
use log::trace;
use thiserror::Error;

use crate::{coroutine::*, imap_try, rfc2971::id::*, rfc3501::capability::*, send::*};

/// Errors that can occur during PLAIN progression.
#[derive(Clone, Debug, Error)]
pub enum ImapAuthPlainError {
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
    #[error("Parse IMAP AUTHENTICATE PLAIN error: unexpected continuation request")]
    UnexpectedContinuationRequest,
    #[error("Parse IMAP AUTHENTICATE PLAIN error: expected continuation request got OK")]
    UnexpectedOk,

    #[error("Send IMAP AUTHENTICATE command error")]
    Send(#[from] SendImapCommandError),
    #[error(transparent)]
    Capability(#[from] ImapCapabilityGetError),
    #[error(transparent)]
    ServerId(#[from] ImapServerIdError),
}

/// Selects the PLAIN sub-flow and any post-authentication
/// round-trips.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImapAuthPlainOptions {
    /// When `true`, embed credentials inline as the SASL initial
    /// response (RFC 4959); the coroutine starts in
    /// [`State::SendIr`]. When `false`, the credentials are uploaded
    /// as continuation data after the server's empty challenge; the
    /// coroutine starts in [`State::Send`].
    pub initial_request: bool,
    pub ensure_capabilities: bool,
    pub auto_id: Option<Vec<(IString<'static>, NString<'static>)>>,
}

/// I/O-free SASL PLAIN coroutine. The initial [`State`] variant
/// ([`State::Send`] vs [`State::SendIr`]) selects between the non-IR
/// and SASL-IR flows.
pub struct ImapAuthPlain {
    state: State,
    observed: Vec<Capability<'static>>,
    opts: ImapAuthPlainOptions,
}

impl ImapAuthPlain {
    /// Creates a new PLAIN coroutine. `opts.initial_request` selects
    /// between the non-IR flow ([`State::Send`]) and the SASL-IR flow
    /// ([`State::SendIr`]).
    ///
    /// `authzid` is the optional authorization identity (RFC 4616);
    /// pass `None` to omit it. `authcid` is the authentication
    /// identity (typically the username).
    pub fn new(
        authzid: Option<impl AsRef<str>>,
        authcid: impl AsRef<str>,
        password: impl AsRef<str>,
        opts: ImapAuthPlainOptions,
    ) -> Self {
        let cid = authcid.as_ref();
        let pass = password.as_ref();
        let payload = match authzid {
            Some(zid) => format!("{}\x00{cid}\x00{pass}", zid.as_ref()).into_bytes(),
            None => format!("\x00{cid}\x00{pass}").into_bytes(),
        };

        let tag = TagGenerator::new().generate();

        let state = if opts.initial_request {
            let body = CommandBody::Authenticate {
                mechanism: AuthMechanism::Plain,
                initial_response: Some(Secret::new(payload.into())),
            };
            let cmd = Command { tag, body };
            trace!("send IMAP command {cmd:?}");
            State::SendIr(SendImapCommand::new(CommandCodec::new(), cmd))
        } else {
            let body = CommandBody::Authenticate {
                mechanism: AuthMechanism::Plain,
                initial_response: None,
            };
            let cmd = Command { tag, body };
            trace!("send IMAP command {cmd:?}");
            State::Send {
                send: SendImapCommand::new(CommandCodec::new(), cmd),
                payload: payload.into(),
            }
        };

        Self {
            state,
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
}

impl ImapCoroutine for ImapAuthPlain {
    type Yield = ImapYield;
    type Return = Result<Vec<Capability<'static>>, ImapAuthPlainError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        loop {
            match &mut self.state {
                State::Send { send, payload } => {
                    let out = imap_try!(send, fragmentizer, arg);

                    if let Some(bye) = out.bye {
                        let err = ImapAuthPlainError::Bye(bye.text.to_string());
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
                            StatusKind::Ok => ImapAuthPlainError::UnexpectedOk,
                            StatusKind::No => ImapAuthPlainError::No(body.text.to_string()),
                            StatusKind::Bad => ImapAuthPlainError::Bad(body.text.to_string()),
                        };

                        return ImapCoroutineState::Complete(Err(err));
                    }

                    let err = ImapAuthPlainError::ExpectedContinuationRequest;
                    return ImapCoroutineState::Complete(Err(err));
                }
                State::SendIr(send) => {
                    let out = imap_try!(send, fragmentizer, arg);

                    if let Some(bye) = out.bye {
                        let err = ImapAuthPlainError::Bye(bye.text.to_string());
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    if out.continuation_request.is_some() {
                        let err = ImapAuthPlainError::UnexpectedContinuationRequest;
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    let Some(Tagged { body, .. }) = out.tagged else {
                        let err = ImapAuthPlainError::MissingTagged;
                        return ImapCoroutineState::Complete(Err(err));
                    };

                    let code = match body.kind {
                        StatusKind::Ok => body.code,
                        StatusKind::No => {
                            let err = ImapAuthPlainError::No(body.text.to_string());
                            return ImapCoroutineState::Complete(Err(err));
                        }
                        StatusKind::Bad => {
                            let err = ImapAuthPlainError::Bad(body.text.to_string());
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
                        let err = ImapAuthPlainError::Bye(bye.text.to_string());
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    if out.continuation_request.is_some() {
                        let err = ImapAuthPlainError::UnexpectedContinuationRequest;
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    let Some(Tagged { body, .. }) = out.tagged else {
                        let err = ImapAuthPlainError::MissingTagged;
                        return ImapCoroutineState::Complete(Err(err));
                    };

                    let code = match body.kind {
                        StatusKind::Ok => body.code,
                        StatusKind::No => {
                            let err = ImapAuthPlainError::No(body.text.to_string());
                            return ImapCoroutineState::Complete(Err(err));
                        }
                        StatusKind::Bad => {
                            let err = ImapAuthPlainError::Bad(body.text.to_string());
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
        payload: Cow<'static, [u8]>,
    },
    SendIr(SendImapCommand<CommandCodec>),
    Continue(SendImapCommand<AuthenticateDataCodec>),
    Capability(ImapCapabilityGet),
    Id(ImapServerId),
}

#[cfg(test)]
mod tests {
    use core::str;

    use super::*;

    /// SASL-IR happy path: credentials sent inline, server accepts on the first
    /// round-trip with tagged OK.
    #[test]
    fn ir_success_returns_ok() {
        let opts = ImapAuthPlainOptions {
            initial_request: true,
            ..Default::default()
        };

        let mut auth = ImapAuthPlain::new(None::<&str>, "alice", "secret", opts);
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut auth, &mut frag, None);
        let line = str::from_utf8(&bytes).expect("utf8 command");
        let tag = first_word(line);
        assert!(line.contains("AUTHENTICATE PLAIN "));

        expect_wants_read(&mut auth, &mut frag);

        let reply = format!("{tag} OK AUTHENTICATE completed\r\n");
        expect_complete_ok(&mut auth, &mut frag, reply.as_bytes());
    }

    /// SASL-IR error path: server rejects the inline credentials with tagged NO.
    #[test]
    fn ir_invalid_credentials_returns_no_error() {
        let opts = ImapAuthPlainOptions {
            initial_request: true,
            ..Default::default()
        };

        let mut auth = ImapAuthPlain::new(None::<&str>, "alice", "wrong", opts);
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut auth, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command"));

        expect_wants_read(&mut auth, &mut frag);

        let reply = format!("{tag} NO authentication failed\r\n");
        let err = expect_complete_err(&mut auth, &mut frag, reply.as_bytes());
        let ImapAuthPlainError::No(text) = err else {
            panic!("expected ImapAuthPlainError::No, got {err:?}");
        };
        assert_eq!(text, "authentication failed");
    }

    /// Tagged BAD before any continuation: surface text verbatim.
    #[test]
    fn ir_tagged_bad_returns_bad_error() {
        let opts = ImapAuthPlainOptions {
            initial_request: true,
            ..Default::default()
        };

        let mut auth = ImapAuthPlain::new(None::<&str>, "alice", "secret", opts);
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut auth, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command"));

        expect_wants_read(&mut auth, &mut frag);

        let reply = format!("{tag} BAD AUTHENTICATE not enabled\r\n");
        let err = expect_complete_err(&mut auth, &mut frag, reply.as_bytes());
        let ImapAuthPlainError::Bad(text) = err else {
            panic!("expected ImapAuthPlainError::Bad, got {err:?}");
        };
        assert_eq!(text, "AUTHENTICATE not enabled");
    }

    /// Non-IR happy path: client sends bare AUTHENTICATE, server answers with
    /// empty continuation challenge, client sends base64-encoded credentials as
    /// continuation data, server returns tagged OK.
    #[test]
    fn non_ir_success_returns_ok() {
        let opts = ImapAuthPlainOptions::default();
        let mut auth = ImapAuthPlain::new(None::<&str>, "alice", "secret", opts);
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut auth, &mut frag, None);
        let line = str::from_utf8(&bytes).expect("utf8 command");
        let tag = first_word(line);
        assert!(line.trim_end().ends_with("AUTHENTICATE PLAIN"));

        expect_wants_read(&mut auth, &mut frag);

        let creds = expect_wants_write(&mut auth, &mut frag, Some(b"+ \r\n"));
        assert!(creds.ends_with(b"\r\n"));

        expect_wants_read(&mut auth, &mut frag);

        let reply = format!("{tag} OK AUTHENTICATE completed\r\n");
        expect_complete_ok(&mut auth, &mut frag, reply.as_bytes());
    }

    /// Non-IR error path: server rejects the uploaded credentials with tagged
    /// NO.
    #[test]
    fn non_ir_invalid_credentials_returns_no_error() {
        let opts = ImapAuthPlainOptions::default();
        let mut auth = ImapAuthPlain::new(None::<&str>, "alice", "wrong", opts);
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut auth, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command"));

        expect_wants_read(&mut auth, &mut frag);
        expect_wants_write(&mut auth, &mut frag, Some(b"+ \r\n"));
        expect_wants_read(&mut auth, &mut frag);

        let reply = format!("{tag} NO authentication failed\r\n");
        let err = expect_complete_err(&mut auth, &mut frag, reply.as_bytes());
        let ImapAuthPlainError::No(text) = err else {
            panic!("expected ImapAuthPlainError::No, got {err:?}");
        };
        assert_eq!(text, "authentication failed");
    }

    // --- utils

    fn expect_wants_write(
        cor: &mut ImapAuthPlain,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> Vec<u8> {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ImapAuthPlain, frag: &mut Fragmentizer) {
        match cor.resume(frag, None) {
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(cor: &mut ImapAuthPlain, frag: &mut Fragmentizer, reply: &[u8]) {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Complete(Ok(_)) => {}
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut ImapAuthPlain,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> ImapAuthPlainError {
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
