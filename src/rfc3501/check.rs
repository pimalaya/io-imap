//! IMAP CHECK coroutine requesting a mailbox checkpoint.
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
//!     rfc3501::check::ImapMailboxCheck,
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negociated, IMAP-authenticated)
//! let mut stream = TcpStream::connect("localhost:143").unwrap();
//!
//! let mut fragmentizer = Fragmentizer::new(50 * 1024 * 1024);
//! let mut buf = [0u8; 4096];
//!
//! let mut coroutine = ImapMailboxCheck::new();
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

/// Failure causes during the IMAP CHECK flow.
#[derive(Clone, Debug, Error)]
pub enum ImapMailboxCheckError {
    #[error("IMAP CHECK failed: NO {0}")]
    No(String),
    #[error("IMAP CHECK failed: BAD {0}")]
    Bad(String),
    #[error("IMAP CHECK failed: BYE {0}")]
    Bye(String),

    #[error("IMAP CHECK failed: server did not return a tagged response")]
    MissingTagged,

    #[error("IMAP CHECK failed: {0}")]
    Send(#[from] SendImapCommandError),
}

/// I/O-free IMAP CHECK coroutine.
pub struct ImapMailboxCheck {
    state: State,
}

impl ImapMailboxCheck {
    pub fn new() -> Self {
        let command = Command {
            tag: TagGenerator::new().generate(),
            body: CommandBody::Check,
        };

        trace!("send IMAP command {command:?}");

        let state = State::Send(SendImapCommand::new(CommandCodec::new(), command));

        Self { state }
    }
}

impl Default for ImapMailboxCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl ImapCoroutine for ImapMailboxCheck {
    type Yield = ImapYield;
    type Return = Result<(), ImapMailboxCheckError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        loop {
            trace!("check: {}", self.state);

            match &mut self.state {
                State::Send(send) => {
                    let out = imap_try!(send, fragmentizer, arg);

                    if let Some(bye) = out.bye {
                        let err = ImapMailboxCheckError::Bye(bye.text.to_string());
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    let Some(Tagged { body, .. }) = out.tagged else {
                        let err = ImapMailboxCheckError::MissingTagged;
                        return ImapCoroutineState::Complete(Err(err));
                    };

                    return match body.kind {
                        StatusKind::Ok => ImapCoroutineState::Complete(Ok(())),
                        StatusKind::No => {
                            let err = ImapMailboxCheckError::No(body.text.to_string());
                            ImapCoroutineState::Complete(Err(err))
                        }
                        StatusKind::Bad => {
                            let err = ImapMailboxCheckError::Bad(body.text.to_string());
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
            Self::Send(_) => f.write_str("send check"),
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
        let mut check = ImapMailboxCheck::new();
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut check, &mut frag, None);
        let line = str::from_utf8(&bytes).expect("utf8 command");
        let tag = first_word(line).to_owned();
        assert!(line.trim_end().ends_with("CHECK"));

        expect_wants_read(&mut check, &mut frag);

        let reply = format!("{tag} OK CHECK completed\r\n");
        expect_complete_ok(&mut check, &mut frag, reply.as_bytes());
    }

    #[test]
    fn tagged_no_returns_no_error() {
        let mut check = ImapMailboxCheck::new();
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut check, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read(&mut check, &mut frag);

        let reply = format!("{tag} NO no mailbox selected\r\n");
        let err = expect_complete_err(&mut check, &mut frag, reply.as_bytes());
        let ImapMailboxCheckError::No(text) = err else {
            panic!("expected ImapMailboxCheckError::No, got {err:?}");
        };
        assert_eq!(text, "no mailbox selected");
    }

    #[test]
    fn tagged_bad_returns_bad_error() {
        let mut check = ImapMailboxCheck::new();
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut check, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read(&mut check, &mut frag);

        let reply = format!("{tag} BAD CHECK syntax error\r\n");
        let err = expect_complete_err(&mut check, &mut frag, reply.as_bytes());
        let ImapMailboxCheckError::Bad(text) = err else {
            panic!("expected ImapMailboxCheckError::Bad, got {err:?}");
        };
        assert_eq!(text, "CHECK syntax error");
    }

    #[test]
    fn bye_returns_bye_error() {
        let mut check = ImapMailboxCheck::new();
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let _ = expect_wants_write(&mut check, &mut frag, None);
        expect_wants_read(&mut check, &mut frag);

        let err = expect_complete_err(&mut check, &mut frag, b"* BYE going down\r\n");
        let ImapMailboxCheckError::Bye(text) = err else {
            panic!("expected ImapMailboxCheckError::Bye, got {err:?}");
        };
        assert_eq!(text, "going down");
    }

    // --- utils

    fn expect_wants_write(
        cor: &mut ImapMailboxCheck,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> Vec<u8> {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ImapMailboxCheck, frag: &mut Fragmentizer) {
        match cor.resume(frag, None) {
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(cor: &mut ImapMailboxCheck, frag: &mut Fragmentizer, reply: &[u8]) {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Complete(Ok(())) => {}
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut ImapMailboxCheck,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> ImapMailboxCheckError {
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
