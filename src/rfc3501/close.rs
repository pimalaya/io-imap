//! IMAP CLOSE coroutine: expunge \Deleted and unselect.
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
//!     rfc3501::close::ImapMailboxClose,
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negociated, IMAP-authenticated)
//! let mut stream = TcpStream::connect("localhost:143").unwrap();
//!
//! let mut fragmentizer = Fragmentizer::new(50 * 1024 * 1024);
//! let mut buf = [0u8; 4096];
//!
//! let mut coroutine = ImapMailboxClose::new();
//! let mut arg = None;
//!
//! loop {
//!     match coroutine.resume(&mut fragmentizer, arg.take()) {
//!         ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         ImapCoroutineState::Complete(Ok(())) => break,
//!         ImapCoroutineState::Complete(Err(err)) => panic!("{err}"),
//!     }
//! }
//! ```

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

/// Failure causes during the IMAP CLOSE flow.
#[derive(Clone, Debug, Error)]
pub enum ImapMailboxCloseError {
    #[error("IMAP CLOSE failed: NO {0}")]
    No(String),
    #[error("IMAP CLOSE failed: BAD {0}")]
    Bad(String),
    #[error("IMAP CLOSE failed: BYE {0}")]
    Bye(String),

    #[error("IMAP CLOSE failed: server did not return a tagged response")]
    MissingTagged,

    #[error("IMAP CLOSE failed: {0}")]
    Send(#[from] SendImapCommandError),
}

/// I/O-free IMAP CLOSE coroutine.
pub struct ImapMailboxClose {
    state: State,
}

impl ImapMailboxClose {
    pub fn new() -> Self {
        let command = Command {
            tag: TagGenerator::new().generate(),
            body: CommandBody::Close,
        };

        trace!("send IMAP command {command:?}");

        let state = State::Send(SendImapCommand::new(CommandCodec::new(), command));

        Self { state }
    }
}

impl Default for ImapMailboxClose {
    fn default() -> Self {
        Self::new()
    }
}

impl ImapCoroutine for ImapMailboxClose {
    type Yield = ImapYield;
    type Return = Result<(), ImapMailboxCloseError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        loop {
            trace!("close: {}", self.state);

            match &mut self.state {
                State::Send(send) => {
                    let out = imap_try!(send, fragmentizer, arg);

                    if let Some(bye) = out.bye {
                        let err = ImapMailboxCloseError::Bye(bye.text.to_string());
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    let Some(Tagged { body, .. }) = out.tagged else {
                        let err = ImapMailboxCloseError::MissingTagged;
                        return ImapCoroutineState::Complete(Err(err));
                    };

                    return match body.kind {
                        StatusKind::Ok => ImapCoroutineState::Complete(Ok(())),
                        StatusKind::No => {
                            let err = ImapMailboxCloseError::No(body.text.to_string());
                            ImapCoroutineState::Complete(Err(err))
                        }
                        StatusKind::Bad => {
                            let err = ImapMailboxCloseError::Bad(body.text.to_string());
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
            Self::Send(_) => f.write_str("send close"),
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
        let mut close = ImapMailboxClose::new();
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut close, &mut frag, None);
        let line = str::from_utf8(&bytes).expect("utf8 command");
        let tag = first_word(line).to_owned();
        assert!(line.trim_end().ends_with("CLOSE"));

        expect_wants_read(&mut close, &mut frag);

        let reply = format!("{tag} OK CLOSE completed\r\n");
        expect_complete_ok(&mut close, &mut frag, reply.as_bytes());
    }

    #[test]
    fn tagged_no_returns_no_error() {
        let mut close = ImapMailboxClose::new();
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut close, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read(&mut close, &mut frag);

        let reply = format!("{tag} NO no mailbox selected\r\n");
        let err = expect_complete_err(&mut close, &mut frag, reply.as_bytes());
        let ImapMailboxCloseError::No(text) = err else {
            panic!("expected ImapMailboxCloseError::No, got {err:?}");
        };
        assert_eq!(text, "no mailbox selected");
    }

    #[test]
    fn tagged_bad_returns_bad_error() {
        let mut close = ImapMailboxClose::new();
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut close, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read(&mut close, &mut frag);

        let reply = format!("{tag} BAD CLOSE syntax error\r\n");
        let err = expect_complete_err(&mut close, &mut frag, reply.as_bytes());
        let ImapMailboxCloseError::Bad(text) = err else {
            panic!("expected ImapMailboxCloseError::Bad, got {err:?}");
        };
        assert_eq!(text, "CLOSE syntax error");
    }

    #[test]
    fn bye_returns_bye_error() {
        let mut close = ImapMailboxClose::new();
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let _ = expect_wants_write(&mut close, &mut frag, None);
        expect_wants_read(&mut close, &mut frag);

        let err = expect_complete_err(&mut close, &mut frag, b"* BYE going down\r\n");
        let ImapMailboxCloseError::Bye(text) = err else {
            panic!("expected ImapMailboxCloseError::Bye, got {err:?}");
        };
        assert_eq!(text, "going down");
    }

    // --- utils

    fn expect_wants_write(
        cor: &mut ImapMailboxClose,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> Vec<u8> {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ImapMailboxClose, frag: &mut Fragmentizer) {
        match cor.resume(frag, None) {
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(cor: &mut ImapMailboxClose, frag: &mut Fragmentizer, reply: &[u8]) {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Complete(Ok(())) => {}
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut ImapMailboxClose,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> ImapMailboxCloseError {
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
