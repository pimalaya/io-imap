//! IMAP EXPUNGE coroutine returning the expunged sequence numbers.
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
//!     rfc3501::expunge::ImapMailboxExpunge,
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negotiated, IMAP-authenticated)
//! let mut stream = TcpStream::connect("localhost:143").unwrap();
//!
//! let mut fragmentizer = Fragmentizer::new(50 * 1024 * 1024);
//! let mut buf = [0u8; 4096];
//!
//! let mut coroutine = ImapMailboxExpunge::new();
//! let mut arg = None;
//!
//! let expunged = loop {
//!     match coroutine.resume(&mut fragmentizer, arg.take()) {
//!         ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         ImapCoroutineState::Complete(Ok(expunged)) => break expunged,
//!         ImapCoroutineState::Complete(Err(err)) => panic!("{err}"),
//!     }
//! };
//!
//! println!("{expunged:?}");
//! ```

use core::{fmt, num::NonZeroU32};

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        command::{Command, CommandBody},
        core::TagGenerator,
        response::{Data, StatusKind, Tagged},
    },
};
use log::trace;
use thiserror::Error;

use crate::{coroutine::*, imap_try, send::*};

/// Failure causes during the IMAP EXPUNGE flow.
#[derive(Clone, Debug, Error)]
pub enum ImapMailboxExpungeError {
    /// The server rejected the command with a NO response.
    #[error("IMAP EXPUNGE failed: NO {0}")]
    No(String),
    /// The server rejected the command with a BAD response.
    #[error("IMAP EXPUNGE failed: BAD {0}")]
    Bad(String),
    /// The server closed the session with an untagged BYE.
    #[error("IMAP EXPUNGE failed: BYE {0}")]
    Bye(String),
    /// The exchange ended without a tagged response from the server.
    #[error("IMAP EXPUNGE failed: server did not return a tagged response")]
    MissingTagged,
    /// The underlying send/receive exchange failed (EOF, decode, framing).
    #[error("IMAP EXPUNGE failed: {0}")]
    Send(#[from] ImapSendError),
}

/// I/O-free IMAP EXPUNGE coroutine.
pub struct ImapMailboxExpunge {
    state: State,
}

impl ImapMailboxExpunge {
    /// Builds an EXPUNGE coroutine removing `\Deleted` messages from the
    /// selected mailbox.
    pub fn new() -> Self {
        let command = Command {
            tag: TagGenerator::new().generate(),
            body: CommandBody::Expunge,
        };

        trace!("send IMAP command {command:?}");

        let state = State::Send(ImapSend::new(CommandCodec::new(), command));

        Self { state }
    }
}

impl Default for ImapMailboxExpunge {
    fn default() -> Self {
        Self::new()
    }
}

impl ImapCoroutine for ImapMailboxExpunge {
    type Yield = ImapYield;
    type Return = Result<Vec<NonZeroU32>, ImapMailboxExpungeError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        match &mut self.state {
            State::Send(send) => {
                let out = imap_try!(send, fragmentizer, arg);

                if let Some(bye) = out.bye {
                    let err = ImapMailboxExpungeError::Bye(bye.text.to_string());
                    return ImapCoroutineState::Complete(Err(err));
                }

                let Some(Tagged { body, .. }) = out.tagged else {
                    let err = ImapMailboxExpungeError::MissingTagged;
                    return ImapCoroutineState::Complete(Err(err));
                };

                let mut expunged = Vec::new();
                for data in out.data {
                    if let Data::Expunge(seq) = data {
                        expunged.push(seq);
                    }
                }

                match body.kind {
                    StatusKind::Ok => ImapCoroutineState::Complete(Ok(expunged)),
                    StatusKind::No => {
                        let err = ImapMailboxExpungeError::No(body.text.to_string());
                        ImapCoroutineState::Complete(Err(err))
                    }
                    StatusKind::Bad => {
                        let err = ImapMailboxExpungeError::Bad(body.text.to_string());
                        ImapCoroutineState::Complete(Err(err))
                    }
                }
            }
        }
    }
}

enum State {
    Send(ImapSend<CommandCodec>),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(_) => f.write_str("send expunge"),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::str;

    use alloc::{borrow::ToOwned, format};

    use crate::rfc3501::expunge::*;

    #[test]
    fn success_collects_expunged_seqs() {
        let mut expunge = ImapMailboxExpunge::new();
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut expunge, &mut frag, None);
        let line = str::from_utf8(&bytes).expect("utf8 command");
        let tag = first_word(line).to_owned();
        assert!(line.trim_end().ends_with("EXPUNGE"));

        expect_wants_read(&mut expunge, &mut frag);

        let reply =
            format!("* 3 EXPUNGE\r\n* 3 EXPUNGE\r\n* 7 EXPUNGE\r\n{tag} OK EXPUNGE completed\r\n",);
        let seqs = expect_complete_ok(&mut expunge, &mut frag, reply.as_bytes());
        assert_eq!(3, seqs.len());
        assert_eq!(3, seqs[0].get());
        assert_eq!(3, seqs[1].get());
        assert_eq!(7, seqs[2].get());
    }

    #[test]
    fn empty_returns_empty_vec() {
        let mut expunge = ImapMailboxExpunge::new();
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut expunge, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read(&mut expunge, &mut frag);

        let reply = format!("{tag} OK EXPUNGE completed\r\n");
        let seqs = expect_complete_ok(&mut expunge, &mut frag, reply.as_bytes());
        assert!(seqs.is_empty());
    }

    #[test]
    fn tagged_no_returns_no_error() {
        let mut expunge = ImapMailboxExpunge::new();
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut expunge, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read(&mut expunge, &mut frag);

        let reply = format!("{tag} NO mailbox is read-only\r\n");
        let err = expect_complete_err(&mut expunge, &mut frag, reply.as_bytes());
        let ImapMailboxExpungeError::No(text) = err else {
            panic!("expected ImapMailboxExpungeError::No, got {err:?}");
        };
        assert_eq!(text, "mailbox is read-only");
    }

    #[test]
    fn bye_returns_bye_error() {
        let mut expunge = ImapMailboxExpunge::new();
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let _ = expect_wants_write(&mut expunge, &mut frag, None);
        expect_wants_read(&mut expunge, &mut frag);

        let err = expect_complete_err(&mut expunge, &mut frag, b"* BYE going down\r\n");
        let ImapMailboxExpungeError::Bye(text) = err else {
            panic!("expected ImapMailboxExpungeError::Bye, got {err:?}");
        };
        assert_eq!(text, "going down");
    }

    fn expect_wants_write(
        cor: &mut ImapMailboxExpunge,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> Vec<u8> {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ImapMailboxExpunge, frag: &mut Fragmentizer) {
        match cor.resume(frag, None) {
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(
        cor: &mut ImapMailboxExpunge,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> Vec<NonZeroU32> {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Complete(Ok(value)) => value,
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut ImapMailboxExpunge,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> ImapMailboxExpungeError {
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
