//! I/O-free coroutine to send an IMAP ID command (RFC 2971).
//!
//! Either form is supported: sending bare `ID NIL` to identify anonymously, or
//! sending `ID (key val ...)` with the caller-supplied parameter list. The
//! response parameter list (if any) is returned on success.

use core::fmt;

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        command::{Command, CommandBody},
        core::{IString, NString, TagGenerator},
        response::{Data, StatusKind, Tagged},
    },
};
use log::trace;
use thiserror::Error;

use crate::{coroutine::*, imap_try, send::*};

/// Errors that can occur during ID progression.
#[derive(Clone, Debug, Error)]
pub enum ImapServerIdError {
    #[error("IMAP ID failed: NO {0}")]
    No(String),
    #[error("IMAP ID failed: BAD {0}")]
    Bad(String),
    #[error("IMAP ID failed: BYE {0}")]
    Bye(String),

    #[error("IMAP ID failed: server did not return a tagged response")]
    MissingTagged,

    #[error("IMAP ID failed: {0}")]
    Send(#[from] SendImapCommandError),
}

/// Options for [`ImapServerId::new`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImapServerIdOptions {
    /// Parameter list sent on the wire. When `None`, the coroutine sends `ID
    /// NIL` (RFC 2971 §3.1, anonymous identification). When `Some(_)`, the
    /// coroutine sends `ID (key val ...)` with the caller-supplied pairs.
    pub parameters: Option<Vec<(IString<'static>, NString<'static>)>>,
}

/// I/O-free IMAP ID coroutine.
pub struct ImapServerId {
    state: State,
}

impl ImapServerId {
    /// Creates a new ID coroutine.
    pub fn new(opts: ImapServerIdOptions) -> Self {
        let command = Command {
            tag: TagGenerator::new().generate(),
            body: CommandBody::Id {
                parameters: opts.parameters,
            },
        };

        trace!("send IMAP command {command:?}");

        let state = State::Send(SendImapCommand::new(CommandCodec::new(), command));

        Self { state }
    }
}

impl ImapCoroutine for ImapServerId {
    type Yield = ImapYield;
    type Return = Result<Option<Vec<(IString<'static>, NString<'static>)>>, ImapServerIdError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        loop {
            trace!("id: {}", self.state);

            match &mut self.state {
                State::Send(send) => {
                    let out = imap_try!(send, fragmentizer, arg);

                    if let Some(bye) = out.bye {
                        let err = ImapServerIdError::Bye(bye.text.to_string());
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    let Some(Tagged { body, .. }) = out.tagged else {
                        return ImapCoroutineState::Complete(Err(ImapServerIdError::MissingTagged));
                    };

                    match body.kind {
                        StatusKind::No => {
                            let err = ImapServerIdError::No(body.text.to_string());
                            return ImapCoroutineState::Complete(Err(err));
                        }
                        StatusKind::Bad => {
                            let err = ImapServerIdError::Bad(body.text.to_string());
                            return ImapCoroutineState::Complete(Err(err));
                        }
                        StatusKind::Ok => {}
                    }

                    let mut server_id = None;
                    for data in out.data {
                        if let Data::Id { parameters } = data {
                            server_id = parameters;
                        }
                    }

                    return ImapCoroutineState::Complete(Ok(server_id));
                }
            }
        }
    }
}

enum State {
    /// Send the ID command and await the tagged response.
    Send(SendImapCommand<CommandCodec>),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(_) => f.write_str("send id"),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::str;

    use alloc::borrow::ToOwned;

    use super::*;

    /// Happy path with `ID NIL`: server replies with `ID NIL`, the
    /// coroutine returns `Ok(None)`.
    #[test]
    fn nil_success_returns_none() {
        let mut id = ImapServerId::new(ImapServerIdOptions::default());
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut id, &mut frag, None);
        let line = str::from_utf8(&bytes).expect("utf8 command");
        let tag = first_word(line).to_owned();
        assert!(line.trim_end().ends_with("ID NIL"));

        expect_wants_read(&mut id, &mut frag);

        let reply = format!("* ID NIL\r\n{tag} OK ID completed\r\n");
        let result = expect_complete_ok(&mut id, &mut frag, reply.as_bytes());
        assert!(result.is_none());
    }

    /// Happy path with server-side parameters: server returns
    /// `ID (key val ...)`, the coroutine surfaces the parsed pairs.
    #[test]
    fn server_parameters_returns_some() {
        let mut id = ImapServerId::new(ImapServerIdOptions::default());
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut id, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read(&mut id, &mut frag);

        let reply =
            format!("* ID (\"name\" \"Dovecot\" \"version\" \"2.3\")\r\n{tag} OK ID completed\r\n");
        let result = expect_complete_ok(&mut id, &mut frag, reply.as_bytes());
        let params = result.expect("server returned parameters");
        assert_eq!(2, params.len());
    }

    /// Tagged NO: surface text verbatim.
    #[test]
    fn tagged_no_returns_no_error() {
        let mut id = ImapServerId::new(ImapServerIdOptions::default());
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut id, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read(&mut id, &mut frag);

        let reply = format!("{tag} NO ID rejected\r\n");
        let err = expect_complete_err(&mut id, &mut frag, reply.as_bytes());
        let ImapServerIdError::No(text) = err else {
            panic!("expected ImapServerIdError::No, got {err:?}");
        };
        assert_eq!(text, "ID rejected");
    }

    /// Tagged BAD: surface text verbatim.
    #[test]
    fn tagged_bad_returns_bad_error() {
        let mut id = ImapServerId::new(ImapServerIdOptions::default());
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut id, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read(&mut id, &mut frag);

        let reply = format!("{tag} BAD ID not supported\r\n");
        let err = expect_complete_err(&mut id, &mut frag, reply.as_bytes());
        let ImapServerIdError::Bad(text) = err else {
            panic!("expected ImapServerIdError::Bad, got {err:?}");
        };
        assert_eq!(text, "ID not supported");
    }

    /// BYE before tagged response: surface text verbatim.
    #[test]
    fn bye_returns_bye_error() {
        let mut id = ImapServerId::new(ImapServerIdOptions::default());
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let _ = expect_wants_write(&mut id, &mut frag, None);
        expect_wants_read(&mut id, &mut frag);

        let err = expect_complete_err(&mut id, &mut frag, b"* BYE shutting down\r\n");
        let ImapServerIdError::Bye(text) = err else {
            panic!("expected ImapServerIdError::Bye, got {err:?}");
        };
        assert_eq!(text, "shutting down");
    }

    // --- utils

    fn expect_wants_write(
        cor: &mut ImapServerId,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> Vec<u8> {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ImapServerId, frag: &mut Fragmentizer) {
        match cor.resume(frag, None) {
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(
        cor: &mut ImapServerId,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> Option<Vec<(IString<'static>, NString<'static>)>> {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Complete(Ok(value)) => value,
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut ImapServerId,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> ImapServerIdError {
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
