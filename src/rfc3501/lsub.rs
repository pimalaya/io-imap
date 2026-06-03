//! IMAP LSUB coroutine returning subscribed mailbox rows.
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
//!     rfc3501::lsub::ImapMailboxLsub,
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negociated, IMAP-authenticated)
//! let mut stream = TcpStream::connect("localhost:143").unwrap();
//!
//! let mut fragmentizer = Fragmentizer::new(50 * 1024 * 1024);
//! let mut buf = [0u8; 4096];
//!
//! let reference = "".try_into().unwrap();
//! let pattern = "*".try_into().unwrap();
//! let mut coroutine = ImapMailboxLsub::new(reference, pattern);
//! let mut arg = None;
//!
//! let mailboxes = loop {
//!     match coroutine.resume(&mut fragmentizer, arg.take()) {
//!         ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         ImapCoroutineState::Complete(Ok(mailboxes)) => break mailboxes,
//!         ImapCoroutineState::Complete(Err(err)) => panic!("{err}"),
//!     }
//! };
//!
//! println!("{mailboxes:?}");
//! ```

use core::fmt;

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        command::{Command, CommandBody},
        core::TagGenerator,
        mailbox::{ListMailbox, Mailbox},
        response::{Data, StatusKind, Tagged},
    },
};
use log::trace;
use thiserror::Error;

use crate::{
    coroutine::*,
    imap_try,
    rfc3501::{
        list::ImapMailboxListing,
        mailbox::{decode_inplace, encode_inplace},
    },
    send::*,
};

/// Failure causes during the IMAP LSUB flow.
#[derive(Clone, Debug, Error)]
pub enum ImapMailboxLsubError {
    #[error("IMAP LSUB failed: NO {0}")]
    No(String),
    #[error("IMAP LSUB failed: BAD {0}")]
    Bad(String),
    #[error("IMAP LSUB failed: BYE {0}")]
    Bye(String),

    #[error("IMAP LSUB failed: server did not return a tagged response")]
    MissingTagged,

    #[error("IMAP LSUB failed: {0}")]
    Send(#[from] SendImapCommandError),
}

/// I/O-free IMAP LSUB coroutine.
pub struct ImapMailboxLsub {
    state: State,
}

impl ImapMailboxLsub {
    pub fn new(mut reference: Mailbox<'static>, mailbox_wildcard: ListMailbox<'static>) -> Self {
        encode_inplace(&mut reference);

        let command = Command {
            tag: TagGenerator::new().generate(),
            body: CommandBody::Lsub {
                reference,
                mailbox_wildcard,
            },
        };

        trace!("send IMAP command {command:?}");

        let state = State::Send(SendImapCommand::new(CommandCodec::new(), command));

        Self { state }
    }
}

impl ImapCoroutine for ImapMailboxLsub {
    type Yield = ImapYield;
    type Return = Result<ImapMailboxListing, ImapMailboxLsubError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        loop {
            trace!("lsub: {}", self.state);

            match &mut self.state {
                State::Send(send) => {
                    let out = imap_try!(send, fragmentizer, arg);

                    if let Some(bye) = out.bye {
                        let err = ImapMailboxLsubError::Bye(bye.text.to_string());
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    let Some(Tagged { body, .. }) = out.tagged else {
                        let err = ImapMailboxLsubError::MissingTagged;
                        return ImapCoroutineState::Complete(Err(err));
                    };

                    let mut mailboxes = Vec::new();
                    for data in out.data {
                        if let Data::Lsub {
                            items,
                            delimiter,
                            mailbox,
                        } = data
                        {
                            let mut mailbox = mailbox;
                            decode_inplace(&mut mailbox);
                            mailboxes.push((mailbox, delimiter, items));
                        }
                    }

                    return match body.kind {
                        StatusKind::Ok => ImapCoroutineState::Complete(Ok(mailboxes)),
                        StatusKind::No => {
                            let err = ImapMailboxLsubError::No(body.text.to_string());
                            ImapCoroutineState::Complete(Err(err))
                        }
                        StatusKind::Bad => {
                            let err = ImapMailboxLsubError::Bad(body.text.to_string());
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
            Self::Send(_) => f.write_str("send lsub"),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::str;

    use alloc::{borrow::ToOwned, vec::Vec};

    use super::*;

    #[test]
    fn success_returns_rows() {
        let mut lsub = ImapMailboxLsub::new(
            "".try_into().expect("valid reference"),
            "*".try_into().expect("valid pattern"),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut lsub, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read(&mut lsub, &mut frag);

        let reply = format!("* LSUB () \"/\" INBOX\r\n{tag} OK LSUB completed\r\n");
        let rows = expect_complete_ok(&mut lsub, &mut frag, reply.as_bytes());
        assert_eq!(1, rows.len());
    }

    #[test]
    fn tagged_no_returns_no_error() {
        let mut lsub = ImapMailboxLsub::new(
            "".try_into().expect("valid reference"),
            "*".try_into().expect("valid pattern"),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut lsub, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read(&mut lsub, &mut frag);

        let reply = format!("{tag} NO not allowed\r\n");
        let err = expect_complete_err(&mut lsub, &mut frag, reply.as_bytes());
        let ImapMailboxLsubError::No(text) = err else {
            panic!("expected ImapMailboxLsubError::No, got {err:?}");
        };
        assert_eq!(text, "not allowed");
    }

    #[test]
    fn bye_returns_bye_error() {
        let mut lsub = ImapMailboxLsub::new(
            "".try_into().expect("valid reference"),
            "*".try_into().expect("valid pattern"),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let _ = expect_wants_write(&mut lsub, &mut frag, None);
        expect_wants_read(&mut lsub, &mut frag);

        let err = expect_complete_err(&mut lsub, &mut frag, b"* BYE going down\r\n");
        let ImapMailboxLsubError::Bye(text) = err else {
            panic!("expected ImapMailboxLsubError::Bye, got {err:?}");
        };
        assert_eq!(text, "going down");
    }

    // --- utils

    fn expect_wants_write(
        cor: &mut ImapMailboxLsub,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> Vec<u8> {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ImapMailboxLsub, frag: &mut Fragmentizer) {
        match cor.resume(frag, None) {
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(
        cor: &mut ImapMailboxLsub,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> ImapMailboxListing {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Complete(Ok(value)) => value,
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut ImapMailboxLsub,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> ImapMailboxLsubError {
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
