//! IMAP RENAME coroutine renaming a mailbox.
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
//!     rfc3501::rename::ImapMailboxRename,
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negociated, IMAP-authenticated)
//! let mut stream = TcpStream::connect("localhost:143").unwrap();
//!
//! let mut fragmentizer = Fragmentizer::new(50 * 1024 * 1024);
//! let mut buf = [0u8; 4096];
//!
//! let from = "Old".try_into().unwrap();
//! let to = "New".try_into().unwrap();
//! let mut coroutine = ImapMailboxRename::new(from, to);
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
        mailbox::Mailbox,
        response::{StatusKind, Tagged},
    },
};
use log::trace;
use thiserror::Error;

use crate::{coroutine::*, imap_try, rfc3501::mailbox::encode_inplace, send::*};

/// Failure causes during the IMAP RENAME flow.
#[derive(Clone, Debug, Error)]
pub enum ImapMailboxRenameError {
    #[error("IMAP RENAME failed: NO {0}")]
    No(String),
    #[error("IMAP RENAME failed: BAD {0}")]
    Bad(String),
    #[error("IMAP RENAME failed: BYE {0}")]
    Bye(String),

    #[error("IMAP RENAME failed: server did not return a tagged response")]
    MissingTagged,

    #[error("IMAP RENAME failed: {0}")]
    Send(#[from] SendImapCommandError),
}

/// I/O-free IMAP RENAME coroutine.
pub struct ImapMailboxRename {
    state: State,
}

impl ImapMailboxRename {
    pub fn new(mut from: Mailbox<'static>, mut to: Mailbox<'static>) -> Self {
        encode_inplace(&mut from);
        encode_inplace(&mut to);

        let command = Command {
            tag: TagGenerator::new().generate(),
            body: CommandBody::Rename { from, to },
        };

        trace!("send IMAP command {command:?}");

        let state = State::Send(SendImapCommand::new(CommandCodec::new(), command));

        Self { state }
    }
}

impl ImapCoroutine for ImapMailboxRename {
    type Yield = ImapYield;
    type Return = Result<(), ImapMailboxRenameError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        loop {
            trace!("rename: {}", self.state);

            match &mut self.state {
                State::Send(send) => {
                    let out = imap_try!(send, fragmentizer, arg);

                    if let Some(bye) = out.bye {
                        let err = ImapMailboxRenameError::Bye(bye.text.to_string());
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    let Some(Tagged { body, .. }) = out.tagged else {
                        let err = ImapMailboxRenameError::MissingTagged;
                        return ImapCoroutineState::Complete(Err(err));
                    };

                    return match body.kind {
                        StatusKind::Ok => ImapCoroutineState::Complete(Ok(())),
                        StatusKind::No => {
                            let err = ImapMailboxRenameError::No(body.text.to_string());
                            ImapCoroutineState::Complete(Err(err))
                        }
                        StatusKind::Bad => {
                            let err = ImapMailboxRenameError::Bad(body.text.to_string());
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
            Self::Send(_) => f.write_str("send rename"),
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
        let mut rename = ImapMailboxRename::new(
            "Old".try_into().expect("valid mailbox"),
            "New".try_into().expect("valid mailbox"),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut rename, &mut frag, None);
        let line = str::from_utf8(&bytes).expect("utf8 command");
        let tag = first_word(line).to_owned();
        assert!(line.contains("RENAME Old New"));

        expect_wants_read(&mut rename, &mut frag);

        let reply = format!("{tag} OK RENAME completed\r\n");
        expect_complete_ok(&mut rename, &mut frag, reply.as_bytes());
    }

    #[test]
    fn tagged_no_returns_no_error() {
        let mut rename = ImapMailboxRename::new(
            "Old".try_into().expect("valid mailbox"),
            "New".try_into().expect("valid mailbox"),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut rename, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read(&mut rename, &mut frag);

        let reply = format!("{tag} NO target mailbox already exists\r\n");
        let err = expect_complete_err(&mut rename, &mut frag, reply.as_bytes());
        let ImapMailboxRenameError::No(text) = err else {
            panic!("expected ImapMailboxRenameError::No, got {err:?}");
        };
        assert_eq!(text, "target mailbox already exists");
    }

    #[test]
    fn bye_returns_bye_error() {
        let mut rename = ImapMailboxRename::new(
            "Old".try_into().expect("valid mailbox"),
            "New".try_into().expect("valid mailbox"),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let _ = expect_wants_write(&mut rename, &mut frag, None);
        expect_wants_read(&mut rename, &mut frag);

        let err = expect_complete_err(&mut rename, &mut frag, b"* BYE going down\r\n");
        let ImapMailboxRenameError::Bye(text) = err else {
            panic!("expected ImapMailboxRenameError::Bye, got {err:?}");
        };
        assert_eq!(text, "going down");
    }

    // --- utils

    fn expect_wants_write(
        cor: &mut ImapMailboxRename,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> Vec<u8> {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ImapMailboxRename, frag: &mut Fragmentizer) {
        match cor.resume(frag, None) {
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(cor: &mut ImapMailboxRename, frag: &mut Fragmentizer, reply: &[u8]) {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Complete(Ok(())) => {}
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut ImapMailboxRename,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> ImapMailboxRenameError {
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
