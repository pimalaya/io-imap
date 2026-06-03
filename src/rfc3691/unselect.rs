//! I/O-free coroutine to send an IMAP UNSELECT command (RFC 3691).
//!
//! Closes the currently selected mailbox without expunging `\Deleted` messages,
//! returning the connection to the authenticated state. No state is returned;
//! success is signalled by the tagged OK alone.

use core::fmt;

use alloc::string::{String, ToString};

use imap_codec::{
    CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        command::{Command, CommandBody},
        core::TagGenerator,
        response::{StatusKind, Tagged},
    },
};
use log::trace;
use thiserror::Error;

use crate::{coroutine::*, imap_try, send::*};

/// Errors that can occur during UNSELECT progression.
#[derive(Clone, Debug, Error)]
pub enum ImapMailboxUnselectError {
    #[error("IMAP UNSELECT failed: NO {0}")]
    No(String),
    #[error("IMAP UNSELECT failed: BAD {0}")]
    Bad(String),
    #[error("IMAP UNSELECT failed: BYE {0}")]
    Bye(String),

    #[error("IMAP UNSELECT failed: server did not return a tagged response")]
    MissingTagged,

    #[error("IMAP UNSELECT failed: {0}")]
    Send(#[from] SendImapCommandError),
}

/// I/O-free IMAP UNSELECT coroutine.
pub struct ImapMailboxUnselect {
    state: State,
}

impl ImapMailboxUnselect {
    /// Creates a new UNSELECT coroutine.
    pub fn new() -> Self {
        let command = Command {
            tag: TagGenerator::new().generate(),
            body: CommandBody::Unselect,
        };

        trace!("send IMAP command {command:?}");

        let state = State::Send(SendImapCommand::new(CommandCodec::new(), command));

        Self { state }
    }
}

impl Default for ImapMailboxUnselect {
    fn default() -> Self {
        Self::new()
    }
}

impl ImapCoroutine for ImapMailboxUnselect {
    type Yield = ImapYield;
    type Return = Result<(), ImapMailboxUnselectError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        loop {
            trace!("unselect: {}", self.state);

            match &mut self.state {
                State::Send(send) => {
                    let out = imap_try!(send, fragmentizer, arg);

                    if let Some(bye) = out.bye {
                        let err = ImapMailboxUnselectError::Bye(bye.text.to_string());
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    let Some(Tagged { body, .. }) = out.tagged else {
                        let err = ImapMailboxUnselectError::MissingTagged;
                        return ImapCoroutineState::Complete(Err(err));
                    };

                    return match body.kind {
                        StatusKind::Ok => ImapCoroutineState::Complete(Ok(())),
                        StatusKind::No => {
                            let err = ImapMailboxUnselectError::No(body.text.to_string());
                            ImapCoroutineState::Complete(Err(err))
                        }
                        StatusKind::Bad => {
                            let err = ImapMailboxUnselectError::Bad(body.text.to_string());
                            ImapCoroutineState::Complete(Err(err))
                        }
                    };
                }
            }
        }
    }
}

enum State {
    /// Send UNSELECT and await the tagged response.
    Send(SendImapCommand<CommandCodec>),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(_) => f.write_str("send unselect"),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::str;

    use alloc::{borrow::ToOwned, vec::Vec};

    use super::*;

    /// Happy path: tagged OK closes the command.
    #[test]
    fn success_returns_ok() {
        let mut unselect = ImapMailboxUnselect::new();
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut unselect, &mut frag, None);
        let line = str::from_utf8(&bytes).expect("utf8 command");
        let tag = first_word(line).to_owned();
        assert!(line.trim_end().ends_with("UNSELECT"));

        expect_wants_read(&mut unselect, &mut frag);

        let reply = format!("{tag} OK UNSELECT completed\r\n");
        expect_complete_ok(&mut unselect, &mut frag, reply.as_bytes());
    }

    /// Tagged NO: surface text verbatim.
    #[test]
    fn tagged_no_returns_no_error() {
        let mut unselect = ImapMailboxUnselect::new();
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut unselect, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read(&mut unselect, &mut frag);

        let reply = format!("{tag} NO no mailbox selected\r\n");
        let err = expect_complete_err(&mut unselect, &mut frag, reply.as_bytes());
        let ImapMailboxUnselectError::No(text) = err else {
            panic!("expected ImapMailboxUnselectError::No, got {err:?}");
        };
        assert_eq!(text, "no mailbox selected");
    }

    /// Tagged BAD: surface text verbatim.
    #[test]
    fn tagged_bad_returns_bad_error() {
        let mut unselect = ImapMailboxUnselect::new();
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut unselect, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read(&mut unselect, &mut frag);

        let reply = format!("{tag} BAD UNSELECT not supported\r\n");
        let err = expect_complete_err(&mut unselect, &mut frag, reply.as_bytes());
        let ImapMailboxUnselectError::Bad(text) = err else {
            panic!("expected ImapMailboxUnselectError::Bad, got {err:?}");
        };
        assert_eq!(text, "UNSELECT not supported");
    }

    /// BYE before tagged response: surface text verbatim.
    #[test]
    fn bye_returns_bye_error() {
        let mut unselect = ImapMailboxUnselect::new();
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let _ = expect_wants_write(&mut unselect, &mut frag, None);
        expect_wants_read(&mut unselect, &mut frag);

        let err = expect_complete_err(&mut unselect, &mut frag, b"* BYE going down\r\n");
        let ImapMailboxUnselectError::Bye(text) = err else {
            panic!("expected ImapMailboxUnselectError::Bye, got {err:?}");
        };
        assert_eq!(text, "going down");
    }

    // --- utils

    fn expect_wants_write(
        cor: &mut ImapMailboxUnselect,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> Vec<u8> {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ImapMailboxUnselect, frag: &mut Fragmentizer) {
        match cor.resume(frag, None) {
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(cor: &mut ImapMailboxUnselect, frag: &mut Fragmentizer, reply: &[u8]) {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Complete(Ok(())) => {}
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut ImapMailboxUnselect,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> ImapMailboxUnselectError {
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
