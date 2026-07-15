//! IMAP APPEND coroutine returning only the APPENDUID pair (NonZeroU32).
//! Lighter than [`crate::rfc3501::append::ImapMessageAppend`]; drops EXISTS.
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
//!     rfc4315::appenduid::{ImapAppendUid, ImapAppendUidOptions},
//!     types::{
//!         core::Literal,
//!         extensions::binary::LiteralOrLiteral8,
//!     },
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negotiated, IMAP-authenticated)
//! let mut stream = TcpStream::connect("localhost:143").unwrap();
//!
//! let mut fragmentizer = Fragmentizer::new(50 * 1024 * 1024);
//! let mut buf = [0u8; 4096];
//!
//! let mailbox = "INBOX".try_into().unwrap();
//! let message = LiteralOrLiteral8::Literal(Literal::unvalidated_non_sync(
//!     b"From: a@b\r\nSubject: hi\r\n\r\nhello",
//! ));
//! let opts = ImapAppendUidOptions::default();
//! let mut coroutine = ImapAppendUid::new(mailbox, message, opts);
//! let mut arg = None;
//!
//! let appenduid = loop {
//!     match coroutine.resume(&mut fragmentizer, arg.take()) {
//!         ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         ImapCoroutineState::Complete(Ok(pair)) => break pair,
//!         ImapCoroutineState::Complete(Err(err)) => panic!("{err}"),
//!     }
//! };
//!
//! println!("{appenduid:?}");
//! ```

use core::{fmt, num::NonZeroU32};

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        command::{Command, CommandBody},
        core::TagGenerator,
        datetime::DateTime,
        extensions::binary::LiteralOrLiteral8,
        flag::Flag,
        mailbox::Mailbox,
        response::{Code, StatusKind, Tagged},
    },
};
use log::trace;
use thiserror::Error;

use crate::{coroutine::*, imap_try, rfc3501::mailbox::encode_inplace, send::*};

/// Failure causes during the APPENDUID-only APPEND flow.
#[derive(Clone, Debug, Error)]
pub enum ImapAppendUidError {
    /// The server rejected the APPEND command with a NO response.
    #[error("IMAP APPEND failed: NO {0}")]
    No(String),
    /// The server rejected the APPEND command with a BAD response.
    #[error("IMAP APPEND failed: BAD {0}")]
    Bad(String),
    /// The server closed the connection with a BYE response.
    #[error("IMAP APPEND failed: BYE {0}")]
    Bye(String),
    /// The server never answered with a tagged response.
    #[error("IMAP APPEND failed: server did not return a tagged response")]
    MissingTagged,
    /// The underlying send sub-coroutine failed.
    #[error("IMAP APPEND failed: {0}")]
    Send(#[from] ImapSendError),
}

/// Options for [`ImapAppendUid::new`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImapAppendUidOptions {
    /// Flags set on the appended message; defaults to none.
    pub flags: Vec<Flag<'static>>,
    /// Internal date of the appended message; defaults to the moment
    /// the server receives it.
    pub date: Option<DateTime>,
}

/// I/O-free IMAP APPEND coroutine returning the APPENDUID pair.
pub struct ImapAppendUid {
    state: State,
}

impl ImapAppendUid {
    /// Creates a coroutine that APPENDs `message` to `mailbox` and
    /// returns the APPENDUID (uidvalidity, uid) pair when present.
    pub fn new(
        mut mailbox: Mailbox<'static>,
        message: LiteralOrLiteral8<'static>,
        opts: ImapAppendUidOptions,
    ) -> Self {
        encode_inplace(&mut mailbox);

        let command = Command {
            tag: TagGenerator::new().generate(),
            body: CommandBody::Append {
                mailbox,
                flags: opts.flags,
                date: opts.date,
                message,
            },
        };

        trace!("send IMAP command {command:?}");

        let state = State::Send(ImapSend::new(CommandCodec::new(), command));

        Self { state }
    }
}

impl ImapCoroutine for ImapAppendUid {
    type Yield = ImapYield;
    type Return = Result<Option<(NonZeroU32, NonZeroU32)>, ImapAppendUidError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        match &mut self.state {
            State::Send(send) => {
                let out = imap_try!(send, fragmentizer, arg);

                if let Some(bye) = out.bye {
                    let err = ImapAppendUidError::Bye(bye.text.to_string());
                    return ImapCoroutineState::Complete(Err(err));
                }

                let Some(Tagged { body, .. }) = out.tagged else {
                    let err = ImapAppendUidError::MissingTagged;
                    return ImapCoroutineState::Complete(Err(err));
                };

                match body.kind {
                    StatusKind::Ok => {
                        let pair = if let Some(Code::AppendUid { uid_validity, uid }) = body.code {
                            Some((uid_validity, uid))
                        } else {
                            None
                        };
                        ImapCoroutineState::Complete(Ok(pair))
                    }
                    StatusKind::No => {
                        let err = ImapAppendUidError::No(body.text.to_string());
                        ImapCoroutineState::Complete(Err(err))
                    }
                    StatusKind::Bad => {
                        let err = ImapAppendUidError::Bad(body.text.to_string());
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
            Self::Send(_) => f.write_str("send append"),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::str;

    use alloc::{borrow::ToOwned, format, vec::Vec};

    use imap_codec::imap_types::core::Literal;

    use crate::rfc4315::appenduid::*;

    #[test]
    fn success_with_appenduid_returns_pair() {
        let message = LiteralOrLiteral8::Literal(Literal::unvalidated_non_sync(b"x"));
        let mut append = ImapAppendUid::new(
            "INBOX".try_into().expect("valid mailbox"),
            message,
            ImapAppendUidOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut append, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read(&mut append, &mut frag);

        let reply = format!("{tag} OK [APPENDUID 1700000000 7] APPEND completed\r\n");
        let pair = expect_complete_ok(&mut append, &mut frag, reply.as_bytes())
            .expect("APPENDUID returned");
        assert_eq!(1700000000, pair.0.get());
        assert_eq!(7, pair.1.get());
    }

    #[test]
    fn success_without_appenduid_returns_none() {
        let message = LiteralOrLiteral8::Literal(Literal::unvalidated_non_sync(b"x"));
        let mut append = ImapAppendUid::new(
            "INBOX".try_into().expect("valid mailbox"),
            message,
            ImapAppendUidOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut append, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read(&mut append, &mut frag);

        let reply = format!("{tag} OK APPEND completed\r\n");
        let pair = expect_complete_ok(&mut append, &mut frag, reply.as_bytes());
        assert!(pair.is_none());
    }

    #[test]
    fn tagged_no_returns_no_error() {
        let message = LiteralOrLiteral8::Literal(Literal::unvalidated_non_sync(b"x"));
        let mut append = ImapAppendUid::new(
            "INBOX".try_into().expect("valid mailbox"),
            message,
            ImapAppendUidOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut append, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read(&mut append, &mut frag);

        let reply = format!("{tag} NO mailbox is read-only\r\n");
        let err = expect_complete_err(&mut append, &mut frag, reply.as_bytes());
        let ImapAppendUidError::No(text) = err else {
            panic!("expected ImapAppendUidError::No, got {err:?}");
        };
        assert_eq!(text, "mailbox is read-only");
    }

    #[test]
    fn bye_returns_bye_error() {
        let message = LiteralOrLiteral8::Literal(Literal::unvalidated_non_sync(b"x"));
        let mut append = ImapAppendUid::new(
            "INBOX".try_into().expect("valid mailbox"),
            message,
            ImapAppendUidOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let _ = expect_wants_write(&mut append, &mut frag, None);
        expect_wants_read(&mut append, &mut frag);

        let err = expect_complete_err(&mut append, &mut frag, b"* BYE going down\r\n");
        let ImapAppendUidError::Bye(text) = err else {
            panic!("expected ImapAppendUidError::Bye, got {err:?}");
        };
        assert_eq!(text, "going down");
    }

    fn expect_wants_write(
        cor: &mut ImapAppendUid,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> Vec<u8> {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ImapAppendUid, frag: &mut Fragmentizer) {
        match cor.resume(frag, None) {
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(
        cor: &mut ImapAppendUid,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> Option<(NonZeroU32, NonZeroU32)> {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Complete(Ok(value)) => value,
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut ImapAppendUid,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> ImapAppendUidError {
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
