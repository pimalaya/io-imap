//! IMAP APPEND coroutine returning the EXISTS count and APPENDUID pair.
//!
//! Buffered: the whole message is held in memory. For large messages, stream
//! it with [`super::append_stream::ImapMessageAppendStream`] instead.
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
//!     rfc3501::append::{ImapMessageAppend, ImapMessageAppendOptions},
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negociated, IMAP-authenticated)
//! let mut stream = TcpStream::connect("localhost:143").unwrap();
//!
//! let mut fragmentizer = Fragmentizer::new(50 * 1024 * 1024);
//! let mut buf = [0u8; 4096];
//!
//! let message = b"From: a@b\r\nSubject: hi\r\n\r\nhello".to_vec();
//! let mailbox = "INBOX".try_into().unwrap();
//! let opts = ImapMessageAppendOptions::default();
//! let mut coroutine = ImapMessageAppend::new(mailbox, message, opts);
//! let mut arg = None;
//!
//! let (exists, appenduid) = loop {
//!     match coroutine.resume(&mut fragmentizer, arg.take()) {
//!         ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         ImapCoroutineState::Complete(Ok(out)) => break out,
//!         ImapCoroutineState::Complete(Err(err)) => panic!("{err}"),
//!     }
//! };
//!
//! println!("exists={exists:?} appenduid={appenduid:?}");
//! ```

use core::fmt;

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        command::{Command, CommandBody},
        core::{Literal, TagGenerator},
        datetime::DateTime,
        extensions::binary::LiteralOrLiteral8,
        flag::Flag,
        mailbox::Mailbox,
        response::{Code, Data, StatusKind, Tagged},
    },
};
use log::trace;
use thiserror::Error;

use crate::{coroutine::*, imap_try, rfc3501::mailbox::encode_inplace, send::*};

/// `(EXISTS count, APPENDUID (uid_validity, uid))`.
pub type ImapMessageAppendOutput = (Option<u32>, Option<(u32, u32)>);

/// Failure causes during the IMAP APPEND flow.
#[derive(Clone, Debug, Error)]
pub enum ImapMessageAppendError {
    #[error("IMAP APPEND failed: NO {0}")]
    No(String),
    #[error("IMAP APPEND failed: BAD {0}")]
    Bad(String),
    #[error("IMAP APPEND failed: BYE {0}")]
    Bye(String),

    #[error("IMAP APPEND failed: server did not return a tagged response")]
    MissingTagged,

    #[error("IMAP APPEND failed: {0}")]
    Send(#[from] SendImapCommandError),
}

/// Options shared by the buffered and streaming APPEND coroutines.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImapMessageAppendOptions {
    pub flags: Vec<Flag<'static>>,
    pub date: Option<DateTime>,
    /// Send a non-synchronising literal (`{N+}`) instead of waiting for the
    /// server continuation. Requires LITERAL+ / LITERAL-, and forfeits early
    /// rejection, so it is best kept for small messages. Defaults to a
    /// synchronising `{N}` literal.
    pub non_sync: bool,
}

/// I/O-free buffered IMAP APPEND coroutine.
pub struct ImapMessageAppend {
    state: State,
}

impl ImapMessageAppend {
    pub fn new(
        mut mailbox: Mailbox<'static>,
        message: Vec<u8>,
        opts: ImapMessageAppendOptions,
    ) -> Self {
        encode_inplace(&mut mailbox);

        let literal = if opts.non_sync {
            Literal::unvalidated_non_sync(message)
        } else {
            Literal::unvalidated(message)
        };

        let command = Command {
            tag: TagGenerator::new().generate(),
            body: CommandBody::Append {
                mailbox,
                flags: opts.flags,
                date: opts.date,
                message: LiteralOrLiteral8::Literal(literal),
            },
        };

        trace!("send IMAP command {command:?}");

        let state = State::Send(SendImapCommand::new(CommandCodec::new(), command));

        Self { state }
    }
}

impl ImapCoroutine for ImapMessageAppend {
    type Yield = ImapYield;
    type Return = Result<ImapMessageAppendOutput, ImapMessageAppendError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        loop {
            trace!("append: {}", self.state);

            match &mut self.state {
                State::Send(send) => {
                    let out = imap_try!(send, fragmentizer, arg);

                    if let Some(bye) = out.bye {
                        let err = ImapMessageAppendError::Bye(bye.text.to_string());
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    let Some(Tagged { body, .. }) = out.tagged else {
                        let err = ImapMessageAppendError::MissingTagged;
                        return ImapCoroutineState::Complete(Err(err));
                    };

                    let mut exists = None;

                    for data in out.data {
                        if let Data::Exists(seq) = data {
                            exists = Some(seq);
                        }
                    }

                    return match body.kind {
                        StatusKind::Ok => {
                            let appenduid =
                                if let Some(Code::AppendUid { uid_validity, uid }) = body.code {
                                    Some((uid_validity.get(), uid.get()))
                                } else {
                                    None
                                };
                            ImapCoroutineState::Complete(Ok((exists, appenduid)))
                        }
                        StatusKind::No => {
                            let err = ImapMessageAppendError::No(body.text.to_string());
                            ImapCoroutineState::Complete(Err(err))
                        }
                        StatusKind::Bad => {
                            let err = ImapMessageAppendError::Bad(body.text.to_string());
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
            Self::Send(_) => f.write_str("send append"),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::str;

    use alloc::borrow::ToOwned;

    use super::*;

    #[test]
    fn sync_success_with_appenduid_returns_pair() {
        let mut append = ImapMessageAppend::new(
            "INBOX".try_into().expect("valid mailbox"),
            b"hi".to_vec(),
            ImapMessageAppendOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let header = expect_wants_write(&mut append, &mut frag, None);
        let line = str::from_utf8(&header).expect("utf8 header");
        let tag = first_word(line).to_owned();
        assert!(line.contains("APPEND INBOX"));
        assert!(line.ends_with("{2}\r\n"));

        // Synchronising literal: wait for `+`, then send the body inline.
        expect_wants_read(&mut append, &mut frag, None);
        let body = expect_wants_write(&mut append, &mut frag, Some(b"+ go\r\n"));
        assert_eq!(body, b"hi\r\n");
        expect_wants_read(&mut append, &mut frag, None);

        let reply = format!("* 1 EXISTS\r\n{tag} OK [APPENDUID 1700000000 7] APPEND completed\r\n");
        let (exists, appenduid) =
            expect_complete_ok(&mut append, &mut frag, Some(reply.as_bytes()));
        assert_eq!(Some(1), exists);
        assert_eq!(Some((1700000000, 7)), appenduid);
    }

    #[test]
    fn non_sync_sends_body_inline() {
        let mut append = ImapMessageAppend::new(
            "INBOX".try_into().expect("valid mailbox"),
            b"hi".to_vec(),
            ImapMessageAppendOptions {
                non_sync: true,
                ..Default::default()
            },
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let header = expect_wants_write(&mut append, &mut frag, None);
        let line = str::from_utf8(&header).expect("utf8 header");
        let tag = first_word(line).to_owned();
        assert!(line.contains("{2+}\r\nhi\r\n"));

        expect_wants_read(&mut append, &mut frag, None);

        let reply = format!("{tag} OK APPEND completed\r\n");
        let (exists, appenduid) =
            expect_complete_ok(&mut append, &mut frag, Some(reply.as_bytes()));
        assert!(exists.is_none());
        assert!(appenduid.is_none());
    }

    #[test]
    fn tagged_no_returns_no_error() {
        let mut append = ImapMessageAppend::new(
            "INBOX".try_into().expect("valid mailbox"),
            b"hi".to_vec(),
            ImapMessageAppendOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let header = expect_wants_write(&mut append, &mut frag, None);
        let tag = first_word(str::from_utf8(&header).expect("utf8 header")).to_owned();

        // The server rejects at the continuation point.
        expect_wants_read(&mut append, &mut frag, None);

        let reply = format!("{tag} NO mailbox is read-only\r\n");
        let err = expect_complete_err(&mut append, &mut frag, Some(reply.as_bytes()));
        let ImapMessageAppendError::No(text) = err else {
            panic!("expected ImapMessageAppendError::No, got {err:?}");
        };
        assert_eq!(text, "mailbox is read-only");
    }

    #[test]
    fn bye_returns_bye_error() {
        let mut append = ImapMessageAppend::new(
            "INBOX".try_into().expect("valid mailbox"),
            b"hi".to_vec(),
            ImapMessageAppendOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let _ = expect_wants_write(&mut append, &mut frag, None);
        expect_wants_read(&mut append, &mut frag, None);

        let err = expect_complete_err(&mut append, &mut frag, Some(b"* BYE shutting down\r\n"));
        let ImapMessageAppendError::Bye(text) = err else {
            panic!("expected ImapMessageAppendError::Bye, got {err:?}");
        };
        assert_eq!(text, "shutting down");
    }

    // --- utils

    fn expect_wants_write(
        cor: &mut ImapMessageAppend,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> Vec<u8> {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ImapMessageAppend, frag: &mut Fragmentizer, arg: Option<&[u8]>) {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(
        cor: &mut ImapMessageAppend,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapMessageAppendOutput {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Complete(Ok(value)) => value,
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut ImapMessageAppend,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapMessageAppendError {
        match cor.resume(frag, arg) {
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
