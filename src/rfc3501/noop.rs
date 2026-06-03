//! IMAP NOOP coroutine, useful as keep-alive or update poll.

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

/// Failure causes during the IMAP NOOP flow.
#[derive(Clone, Debug, Error)]
pub enum ImapNoopError {
    #[error("IMAP NOOP failed: NO {0}")]
    No(String),
    #[error("IMAP NOOP failed: BAD {0}")]
    Bad(String),
    #[error("IMAP NOOP failed: BYE {0}")]
    Bye(String),

    #[error("IMAP NOOP failed: server did not return a tagged response")]
    MissingTagged,

    #[error("IMAP NOOP failed: {0}")]
    Send(#[from] SendImapCommandError),
}

/// I/O-free IMAP NOOP coroutine.
pub struct ImapNoop {
    state: State,
}

impl ImapNoop {
    pub fn new() -> Self {
        let command = Command {
            tag: TagGenerator::new().generate(),
            body: CommandBody::Noop,
        };

        trace!("send IMAP command {command:?}");

        let state = State::Send(SendImapCommand::new(CommandCodec::new(), command));

        Self { state }
    }
}

impl Default for ImapNoop {
    fn default() -> Self {
        Self::new()
    }
}

impl ImapCoroutine for ImapNoop {
    type Yield = ImapYield;
    type Return = Result<(), ImapNoopError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        loop {
            trace!("noop: {}", self.state);

            match &mut self.state {
                State::Send(send) => {
                    let out = imap_try!(send, fragmentizer, arg);

                    if let Some(bye) = out.bye {
                        let err = ImapNoopError::Bye(bye.text.to_string());
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    let Some(Tagged { body, .. }) = out.tagged else {
                        let err = ImapNoopError::MissingTagged;
                        return ImapCoroutineState::Complete(Err(err));
                    };

                    return match body.kind {
                        StatusKind::Ok => ImapCoroutineState::Complete(Ok(())),
                        StatusKind::No => {
                            let err = ImapNoopError::No(body.text.to_string());
                            ImapCoroutineState::Complete(Err(err))
                        }
                        StatusKind::Bad => {
                            let err = ImapNoopError::Bad(body.text.to_string());
                            ImapCoroutineState::Complete(Err(err))
                        }
                    };
                }
            }
        }
    }
}

enum State {
    Send(SendImapCommand<CommandCodec>),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(_) => f.write_str("send noop"),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::str;

    use alloc::{borrow::ToOwned, vec::Vec};

    use super::*;

    #[test]
    fn success_returns_ok() {
        let mut noop = ImapNoop::new();
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut noop, &mut frag, None);
        let line = str::from_utf8(&bytes).expect("utf8 command");
        let tag = first_word(line).to_owned();
        assert!(line.trim_end().ends_with("NOOP"));

        expect_wants_read(&mut noop, &mut frag);

        let reply = format!("{tag} OK NOOP completed\r\n");
        expect_complete_ok(&mut noop, &mut frag, reply.as_bytes());
    }

    #[test]
    fn tagged_bad_returns_bad_error() {
        let mut noop = ImapNoop::new();
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut noop, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read(&mut noop, &mut frag);

        let reply = format!("{tag} BAD NOOP syntax error\r\n");
        let err = expect_complete_err(&mut noop, &mut frag, reply.as_bytes());
        let ImapNoopError::Bad(text) = err else {
            panic!("expected ImapNoopError::Bad, got {err:?}");
        };
        assert_eq!(text, "NOOP syntax error");
    }

    #[test]
    fn bye_returns_bye_error() {
        let mut noop = ImapNoop::new();
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let _ = expect_wants_write(&mut noop, &mut frag, None);
        expect_wants_read(&mut noop, &mut frag);

        let err = expect_complete_err(&mut noop, &mut frag, b"* BYE going down\r\n");
        let ImapNoopError::Bye(text) = err else {
            panic!("expected ImapNoopError::Bye, got {err:?}");
        };
        assert_eq!(text, "going down");
    }

    // --- utils

    fn expect_wants_write(
        cor: &mut ImapNoop,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> Vec<u8> {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ImapNoop, frag: &mut Fragmentizer) {
        match cor.resume(frag, None) {
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(cor: &mut ImapNoop, frag: &mut Fragmentizer, reply: &[u8]) {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Complete(Ok(())) => {}
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut ImapNoop,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> ImapNoopError {
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
