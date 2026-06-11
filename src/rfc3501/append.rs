//! IMAP APPEND coroutine streaming the message body and returning the EXISTS
//! count and APPENDUID pair.
//!
//! The body is never held whole: [`ImapMessageAppend::new`] takes only the
//! octet count (IMAP declares it up front in the literal), and the coroutine
//! yields [`ImapMessageAppendYield::WantsStream`] so the driver pumps the bytes
//! straight from its own source to the socket.
//!
//! # Example
//!
//! ```rust,no_run
//! use std::{
//!     io::{self, Read, Write},
//!     net::TcpStream,
//! };
//!
//! use io_imap::{
//!     codec::fragmentizer::Fragmentizer,
//!     coroutine::{ImapCoroutine, ImapCoroutineState},
//!     rfc3501::append::{ImapMessageAppendYield, ImapMessageAppend, ImapMessageAppendOptions},
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negociated, IMAP-authenticated)
//! let mut stream = TcpStream::connect("localhost:143").unwrap();
//!
//! let mut fragmentizer = Fragmentizer::new(50 * 1024 * 1024);
//! let mut buf = [0u8; 4096];
//!
//! let message: &[u8] = b"From: a@b\r\nSubject: hi\r\n\r\nhello";
//! let mut body = message;
//! let mailbox = "INBOX".try_into().unwrap();
//! let opts = ImapMessageAppendOptions::default();
//! let mut coroutine = ImapMessageAppend::new(mailbox, message.len() as u32, opts);
//! let mut arg = None;
//!
//! let (exists, appenduid) = loop {
//!     match coroutine.resume(&mut fragmentizer, arg.take()) {
//!         ImapCoroutineState::Yielded(ImapMessageAppendYield::WantsWrite(bytes)) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         ImapCoroutineState::Yielded(ImapMessageAppendYield::WantsRead) => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         ImapCoroutineState::Yielded(ImapMessageAppendYield::WantsStream) => {
//!             io::copy(&mut body, &mut stream).unwrap();
//!         }
//!         ImapCoroutineState::Complete(Ok(out)) => break out,
//!         ImapCoroutineState::Complete(Err(err)) => panic!("{err}"),
//!     }
//! };
//!
//! println!("exists={exists:?} appenduid={appenduid:?}");
//! ```

use core::fmt;

use alloc::{format, string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    encode::{Encoder, Fragment},
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
    #[error("IMAP APPEND failed: message source delivered fewer octets than declared")]
    ShortMessage,

    #[error("IMAP APPEND failed: {0}")]
    Send(#[from] SendImapCommandError),
}

/// Options for [`ImapMessageAppend::new`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImapMessageAppendOptions {
    pub flags: Vec<Flag<'static>>,
    pub date: Option<DateTime>,
    /// Send a non-synchronising literal (`{N+}`) and stream the body
    /// without waiting for the server continuation. Requires LITERAL+ /
    /// LITERAL-, and forfeits early rejection, so it is best kept for
    /// small messages. Defaults to a synchronising `{N}` literal.
    pub non_sync: bool,
}

/// I/O-free IMAP APPEND coroutine streaming the message body.
pub struct ImapMessageAppend {
    state: State,
    header: Option<Vec<u8>>,
    crlf: Option<Vec<u8>>,
    command: Command<'static>,
    non_sync: bool,
    stream_pending: bool,
}

impl ImapMessageAppend {
    pub fn new(mut mailbox: Mailbox<'static>, len: u32, opts: ImapMessageAppendOptions) -> Self {
        encode_inplace(&mut mailbox);

        // Build the request line through imap-codec with an empty
        // literal, then splice in the real octet count: streaming keeps
        // the message body out of the encoder so it never lands in
        // memory whole.
        let command = Command {
            tag: TagGenerator::new().generate(),
            body: CommandBody::Append {
                mailbox,
                flags: opts.flags,
                date: opts.date,
                message: LiteralOrLiteral8::Literal(Literal::unvalidated_non_sync(Vec::new())),
            },
        };

        trace!("send IMAP command {command:?}");

        let fragments: Vec<Fragment> = CommandCodec::new().encode(&command).collect();

        // The message literal is the last literal fragment: the lines
        // before it form the request header, the line after it the
        // command-closing CRLF that follows the streamed body. The empty
        // literal itself is dropped.
        let last = fragments
            .iter()
            .rposition(|fragment| matches!(fragment, Fragment::Literal { .. }))
            .expect("APPEND always encodes a message literal");

        let mut header = Vec::new();
        let mut crlf = Vec::new();

        for (index, fragment) in fragments.into_iter().enumerate() {
            match fragment {
                Fragment::Line { data } if index < last => header.extend(data),
                Fragment::Line { data } => crlf.extend(data),
                // NOTE: a mailbox literal (rare) precedes the message one and
                // belongs inline in the header.
                Fragment::Literal { data, .. } if index < last => header.extend(data),
                Fragment::Literal { .. } => {}
            }
        }

        // imap-codec emitted the empty literal header as `{0+}\r\n`; rewrite it
        // with the real count, synchronising unless `non_sync` was requested.
        const EMPTY_LITERAL: &[u8] = b"{0+}\r\n";
        debug_assert!(header.ends_with(EMPTY_LITERAL));
        header.truncate(header.len() - EMPTY_LITERAL.len());

        if opts.non_sync {
            header.extend_from_slice(format!("{{{len}+}}\r\n").as_bytes());
        } else {
            header.extend_from_slice(format!("{{{len}}}\r\n").as_bytes());
        }

        Self {
            state: State::WriteHeader,
            header: Some(header),
            crlf: Some(crlf),
            command,
            non_sync: opts.non_sync,
            stream_pending: false,
        }
    }
}

impl ImapCoroutine for ImapMessageAppend {
    type Yield = ImapMessageAppendYield;
    type Return = Result<ImapMessageAppendOutput, ImapMessageAppendError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        loop {
            trace!("append: {}", self.state);

            match &mut self.state {
                State::WriteHeader => {
                    let header = self.header.take().expect("header written once");

                    // Synchronising literals wait for the server `+`
                    // before the body; non-synchronising ones stream
                    // straight away.
                    self.state = if self.non_sync {
                        State::Stream
                    } else {
                        State::Continuation(SendImapCommand::receive(self.command.clone()))
                    };

                    return ImapCoroutineState::Yielded(ImapMessageAppendYield::WantsWrite(header));
                }
                State::Continuation(recv) => {
                    let out = imap_try!(recv, fragmentizer, arg);

                    if let Some(bye) = out.bye {
                        let err = ImapMessageAppendError::Bye(bye.text.to_string());
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    // A tagged response before the continuation means the
                    // server refused the append up front.
                    if let Some(Tagged { body, .. }) = out.tagged {
                        let err = match body.kind {
                            StatusKind::No => ImapMessageAppendError::No(body.text.to_string()),
                            _ => ImapMessageAppendError::Bad(body.text.to_string()),
                        };
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    self.state = State::Stream;
                }
                State::Stream => {
                    if self.stream_pending {
                        self.stream_pending = false;

                        if matches!(arg, Some(&[])) {
                            let err = ImapMessageAppendError::ShortMessage;
                            return ImapCoroutineState::Complete(Err(err));
                        }

                        self.state = State::WriteCrlf;
                        continue;
                    }

                    self.stream_pending = true;
                    return ImapCoroutineState::Yielded(ImapMessageAppendYield::WantsStream);
                }
                State::WriteCrlf => {
                    let crlf = self.crlf.take().expect("crlf written once");
                    self.state = State::Recv(SendImapCommand::receive(self.command.clone()));
                    return ImapCoroutineState::Yielded(ImapMessageAppendYield::WantsWrite(crlf));
                }
                State::Recv(recv) => {
                    let out = imap_try!(recv, fragmentizer, arg);

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

/// Yield variants from the APPEND coroutine.
#[derive(Debug)]
pub enum ImapMessageAppendYield {
    WantsRead,
    WantsWrite(Vec<u8>),
    /// Stream exactly the declared message octets to the server, then resume
    /// with `None` on success or `Some(&[])` if the source ran short.
    WantsStream,
}

impl From<ImapYield> for ImapMessageAppendYield {
    fn from(yielded: ImapYield) -> Self {
        match yielded {
            ImapYield::WantsRead => Self::WantsRead,
            ImapYield::WantsWrite(bytes) => Self::WantsWrite(bytes),
        }
    }
}

enum State {
    WriteHeader,
    Continuation(SendImapCommand<CommandCodec>),
    Stream,
    WriteCrlf,
    Recv(SendImapCommand<CommandCodec>),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WriteHeader => f.write_str("write append header"),
            Self::Continuation(_) => f.write_str("await continuation"),
            Self::Stream => f.write_str("stream message"),
            Self::WriteCrlf => f.write_str("write append crlf"),
            Self::Recv(_) => f.write_str("receive append response"),
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
            15,
            ImapMessageAppendOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let header = expect_wants_write(&mut append, &mut frag, None);
        let line = str::from_utf8(&header).expect("utf8 header");
        let tag = first_word(line).to_owned();
        assert!(line.contains("APPEND INBOX"));
        assert!(line.ends_with("{15}\r\n"));

        expect_wants_read(&mut append, &mut frag, None);
        expect_wants_stream(
            &mut append,
            &mut frag,
            Some(b"+ Ready for literal data\r\n"),
        );

        let crlf = expect_wants_write(&mut append, &mut frag, None);
        assert_eq!(crlf, b"\r\n");

        expect_wants_read(&mut append, &mut frag, None);

        let reply =
            format!("* 42 EXISTS\r\n{tag} OK [APPENDUID 1700000000 7] APPEND completed\r\n");
        let (exists, appenduid) =
            expect_complete_ok(&mut append, &mut frag, Some(reply.as_bytes()));
        assert_eq!(Some(42), exists);
        assert_eq!(Some((1700000000, 7)), appenduid);
    }

    #[test]
    fn sync_success_without_appenduid_returns_none_uid() {
        let mut append = ImapMessageAppend::new(
            "INBOX".try_into().expect("valid mailbox"),
            1,
            ImapMessageAppendOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let header = expect_wants_write(&mut append, &mut frag, None);
        let tag = first_word(str::from_utf8(&header).expect("utf8 header")).to_owned();

        expect_wants_read(&mut append, &mut frag, None);
        expect_wants_stream(&mut append, &mut frag, Some(b"+ go\r\n"));
        let _ = expect_wants_write(&mut append, &mut frag, None);
        expect_wants_read(&mut append, &mut frag, None);

        let reply = format!("{tag} OK APPEND completed\r\n");
        let (exists, appenduid) =
            expect_complete_ok(&mut append, &mut frag, Some(reply.as_bytes()));
        assert!(exists.is_none());
        assert!(appenduid.is_none());
    }

    #[test]
    fn non_sync_streams_without_continuation() {
        let mut append = ImapMessageAppend::new(
            "INBOX".try_into().expect("valid mailbox"),
            15,
            ImapMessageAppendOptions {
                non_sync: true,
                ..Default::default()
            },
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let header = expect_wants_write(&mut append, &mut frag, None);
        let line = str::from_utf8(&header).expect("utf8 header");
        let tag = first_word(line).to_owned();
        assert!(line.ends_with("{15+}\r\n"));

        // No continuation read: the body streams straight away.
        expect_wants_stream(&mut append, &mut frag, None);
        let crlf = expect_wants_write(&mut append, &mut frag, None);
        assert_eq!(crlf, b"\r\n");

        expect_wants_read(&mut append, &mut frag, None);

        let reply = format!("{tag} OK APPEND completed\r\n");
        expect_complete_ok(&mut append, &mut frag, Some(reply.as_bytes()));
    }

    #[test]
    fn continuation_no_returns_no_error() {
        let mut append = ImapMessageAppend::new(
            "INBOX".try_into().expect("valid mailbox"),
            15,
            ImapMessageAppendOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let header = expect_wants_write(&mut append, &mut frag, None);
        let tag = first_word(str::from_utf8(&header).expect("utf8 header")).to_owned();

        expect_wants_read(&mut append, &mut frag, None);

        let reply = format!("{tag} NO over quota\r\n");
        let err = expect_complete_err(&mut append, &mut frag, Some(reply.as_bytes()));
        let ImapMessageAppendError::No(text) = err else {
            panic!("expected ImapMessageAppendError::No, got {err:?}");
        };
        assert_eq!(text, "over quota");
    }

    #[test]
    fn tagged_bad_returns_bad_error() {
        let mut append = ImapMessageAppend::new(
            "INBOX".try_into().expect("valid mailbox"),
            15,
            ImapMessageAppendOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let header = expect_wants_write(&mut append, &mut frag, None);
        let tag = first_word(str::from_utf8(&header).expect("utf8 header")).to_owned();

        expect_wants_read(&mut append, &mut frag, None);
        expect_wants_stream(&mut append, &mut frag, Some(b"+ go\r\n"));
        let _ = expect_wants_write(&mut append, &mut frag, None);
        expect_wants_read(&mut append, &mut frag, None);

        let reply = format!("{tag} BAD APPEND syntax error\r\n");
        let err = expect_complete_err(&mut append, &mut frag, Some(reply.as_bytes()));
        let ImapMessageAppendError::Bad(text) = err else {
            panic!("expected ImapMessageAppendError::Bad, got {err:?}");
        };
        assert_eq!(text, "APPEND syntax error");
    }

    #[test]
    fn short_stream_returns_short_message_error() {
        let mut append = ImapMessageAppend::new(
            "INBOX".try_into().expect("valid mailbox"),
            15,
            ImapMessageAppendOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let _ = expect_wants_write(&mut append, &mut frag, None);
        expect_wants_read(&mut append, &mut frag, None);
        expect_wants_stream(&mut append, &mut frag, Some(b"+ go\r\n"));

        // Driver signals a short source with an empty slice.
        let err = expect_complete_err(&mut append, &mut frag, Some(&[]));
        assert!(matches!(err, ImapMessageAppendError::ShortMessage));
    }

    #[test]
    fn bye_returns_bye_error() {
        let mut append = ImapMessageAppend::new(
            "INBOX".try_into().expect("valid mailbox"),
            15,
            ImapMessageAppendOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let _ = expect_wants_write(&mut append, &mut frag, None);
        expect_wants_read(&mut append, &mut frag, None);
        expect_wants_stream(&mut append, &mut frag, Some(b"+ go\r\n"));
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
            ImapCoroutineState::Yielded(ImapMessageAppendYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ImapMessageAppend, frag: &mut Fragmentizer, arg: Option<&[u8]>) {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapMessageAppendYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_wants_stream(
        cor: &mut ImapMessageAppend,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapMessageAppendYield::WantsStream) => {}
            state => panic!("expected WantsStream, got {state:?}"),
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
