//! IMAP APPEND coroutine streaming the message body and returning the EXISTS
//! count and APPENDUID pair.
//!
//! The body is never held whole: [`ImapMessageAppendStream::new`] takes only
//! the octet count (IMAP declares it up front in the literal), and the
//! coroutine yields [`ImapMessageAppendStreamYield::WantsStream`] so the
//! caller pumps the bytes straight from its own source to the socket. Use
//! [`super::append::ImapMessageAppend`] when the whole message already fits
//! in memory.
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
//!     rfc3501::{
//!         append::ImapMessageAppendOptions,
//!         append_stream::{
//!             ImapMessageAppendStream, ImapMessageAppendStreamYield,
//!         },
//!     },
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negotiated, IMAP-authenticated)
//! let mut stream = TcpStream::connect("localhost:143").unwrap();
//!
//! let mut fragmentizer = Fragmentizer::new(50 * 1024 * 1024);
//! let mut buf = [0u8; 4096];
//!
//! let message: &[u8] = b"From: a@b\r\nSubject: hi\r\n\r\nhello";
//! let mut body = message;
//! let mailbox = "INBOX".try_into().unwrap();
//! let opts = ImapMessageAppendOptions::default();
//! let len = message.len() as u32;
//! let mut coroutine = ImapMessageAppendStream::new(mailbox, len, opts);
//! let mut arg = None;
//!
//! let (exists, appenduid) = loop {
//!     match coroutine.resume(&mut fragmentizer, arg.take()) {
//!         ImapCoroutineState::Yielded(
//!             ImapMessageAppendStreamYield::WantsWrite(bytes),
//!         ) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         ImapCoroutineState::Yielded(
//!             ImapMessageAppendStreamYield::WantsRead,
//!         ) => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         ImapCoroutineState::Yielded(
//!             ImapMessageAppendStreamYield::WantsStream,
//!         ) => {
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
        extensions::binary::LiteralOrLiteral8,
        mailbox::Mailbox,
        response::{Code, Data, StatusKind, Tagged},
    },
};
use log::{debug, trace};
use thiserror::Error;

use crate::{
    coroutine::*,
    imap_try,
    rfc3501::{
        append::{ImapMessageAppendOptions, ImapMessageAppendOutput},
        mailbox::encode_inplace,
    },
    send::*,
};

/// Failure causes during the IMAP APPEND streaming flow.
#[derive(Clone, Debug, Error)]
pub enum ImapMessageAppendStreamError {
    /// The server rejected the command with a NO response.
    #[error("IMAP APPEND failed: NO {0}")]
    No(String),
    /// The server rejected the command with a BAD response.
    #[error("IMAP APPEND failed: BAD {0}")]
    Bad(String),
    /// The server closed the session with an untagged BYE.
    #[error("IMAP APPEND failed: BYE {0}")]
    Bye(String),
    /// The exchange ended without a tagged response from the server.
    #[error("IMAP APPEND failed: server did not return a tagged response")]
    MissingTagged,
    /// The message source delivered fewer octets than the declared
    /// literal length.
    #[error("IMAP APPEND failed: message source delivered fewer octets than declared")]
    ShortMessage,
    /// The underlying send/receive exchange failed (EOF, decode, framing).
    #[error("IMAP APPEND failed: {0}")]
    Send(#[from] ImapSendError),
}

/// Yield variants from the streaming APPEND coroutine.
#[derive(Debug)]
pub enum ImapMessageAppendStreamYield {
    /// The caller reads from its stream and resumes with the bytes.
    WantsRead,
    /// The caller writes the given bytes to its stream and resumes.
    WantsWrite(Vec<u8>),
    /// Stream exactly the declared message octets to the server, then resume
    /// with `None` on success or `Some(&[])` if the source ran short.
    WantsStream,
}

impl From<ImapYield> for ImapMessageAppendStreamYield {
    fn from(yielded: ImapYield) -> Self {
        match yielded {
            ImapYield::WantsRead => Self::WantsRead,
            ImapYield::WantsWrite(bytes) => Self::WantsWrite(bytes),
        }
    }
}

/// I/O-free IMAP APPEND coroutine streaming the message body.
pub struct ImapMessageAppendStream {
    state: State,
    header: Option<Vec<u8>>,
    crlf: Option<Vec<u8>>,
    command: Command<'static>,
    non_sync: bool,
    stream_pending: bool,
}

impl ImapMessageAppendStream {
    /// Builds a streaming APPEND coroutine appending a `len`-octet message
    /// to `mailbox`.
    ///
    /// The body bytes never pass through the coroutine: it yields
    /// [`ImapMessageAppendStreamYield::WantsStream`] and the caller pumps
    /// exactly `len` octets from its own source to the socket.
    pub fn new(mut mailbox: Mailbox<'static>, len: u32, opts: ImapMessageAppendOptions) -> Self {
        encode_inplace(&mut mailbox);

        // NOTE: build the request line through imap-codec with an empty
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

        // NOTE: the message literal is the last literal fragment: the lines
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

        // NOTE: imap-codec emitted the empty literal header as
        // `{0+}\r\n`; rewrite it with the real count, synchronising
        // unless `non_sync` was requested.
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

impl ImapCoroutine for ImapMessageAppendStream {
    type Yield = ImapMessageAppendStreamYield;
    type Return = Result<ImapMessageAppendOutput, ImapMessageAppendStreamError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        loop {
            match &mut self.state {
                State::WriteHeader => {
                    let header = self.header.take().expect("header written once");

                    // NOTE: synchronising literals wait for the server
                    // `+` before the body; non-synchronising ones stream
                    // straight away.
                    self.state = if self.non_sync {
                        State::Stream
                    } else {
                        State::Continuation(ImapSend::receive(self.command.clone()))
                    };
                    debug!("{}", self.state);

                    return ImapCoroutineState::Yielded(ImapMessageAppendStreamYield::WantsWrite(
                        header,
                    ));
                }
                State::Continuation(recv) => {
                    let out = imap_try!(recv, fragmentizer, arg);

                    if let Some(bye) = out.bye {
                        let err = ImapMessageAppendStreamError::Bye(bye.text.to_string());
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    // NOTE: a tagged response before the continuation
                    // means the server refused the append up front.
                    if let Some(Tagged { body, .. }) = out.tagged {
                        let err = match body.kind {
                            StatusKind::No => {
                                ImapMessageAppendStreamError::No(body.text.to_string())
                            }
                            _ => ImapMessageAppendStreamError::Bad(body.text.to_string()),
                        };
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    self.state = State::Stream;
                    debug!("{}", self.state);
                }
                State::Stream => {
                    if self.stream_pending {
                        self.stream_pending = false;

                        if matches!(arg, Some(&[])) {
                            let err = ImapMessageAppendStreamError::ShortMessage;
                            return ImapCoroutineState::Complete(Err(err));
                        }

                        self.state = State::WriteCrlf;
                        debug!("{}", self.state);
                        continue;
                    }

                    self.stream_pending = true;
                    return ImapCoroutineState::Yielded(ImapMessageAppendStreamYield::WantsStream);
                }
                State::WriteCrlf => {
                    let crlf = self.crlf.take().expect("crlf written once");
                    self.state = State::Recv(ImapSend::receive(self.command.clone()));
                    debug!("{}", self.state);
                    return ImapCoroutineState::Yielded(ImapMessageAppendStreamYield::WantsWrite(
                        crlf,
                    ));
                }
                State::Recv(recv) => {
                    let out = imap_try!(recv, fragmentizer, arg);

                    if let Some(bye) = out.bye {
                        let err = ImapMessageAppendStreamError::Bye(bye.text.to_string());
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    let Some(Tagged { body, .. }) = out.tagged else {
                        let err = ImapMessageAppendStreamError::MissingTagged;
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
                            let err = ImapMessageAppendStreamError::No(body.text.to_string());
                            ImapCoroutineState::Complete(Err(err))
                        }
                        StatusKind::Bad => {
                            let err = ImapMessageAppendStreamError::Bad(body.text.to_string());
                            ImapCoroutineState::Complete(Err(err))
                        }
                    };
                }
            }
        }
    }
}

enum State {
    WriteHeader,
    Continuation(ImapSend<CommandCodec>),
    Stream,
    WriteCrlf,
    Recv(ImapSend<CommandCodec>),
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

    use crate::rfc3501::append_stream::*;

    #[test]
    fn sync_success_with_appenduid_returns_pair() {
        let mut append = ImapMessageAppendStream::new(
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
    fn non_sync_streams_without_continuation() {
        let mut append = ImapMessageAppendStream::new(
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

        // NOTE: no continuation read: the body streams straight away.
        expect_wants_stream(&mut append, &mut frag, None);
        let crlf = expect_wants_write(&mut append, &mut frag, None);
        assert_eq!(crlf, b"\r\n");

        expect_wants_read(&mut append, &mut frag, None);

        let reply = format!("{tag} OK APPEND completed\r\n");
        expect_complete_ok(&mut append, &mut frag, Some(reply.as_bytes()));
    }

    #[test]
    fn continuation_no_returns_no_error() {
        let mut append = ImapMessageAppendStream::new(
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
        let ImapMessageAppendStreamError::No(text) = err else {
            panic!("expected ImapMessageAppendStreamError::No, got {err:?}");
        };
        assert_eq!(text, "over quota");
    }

    #[test]
    fn short_stream_returns_short_message_error() {
        let mut append = ImapMessageAppendStream::new(
            "INBOX".try_into().expect("valid mailbox"),
            15,
            ImapMessageAppendOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let _ = expect_wants_write(&mut append, &mut frag, None);
        expect_wants_read(&mut append, &mut frag, None);
        expect_wants_stream(&mut append, &mut frag, Some(b"+ go\r\n"));

        // NOTE: an empty slice signals a short source.
        let err = expect_complete_err(&mut append, &mut frag, Some(&[]));
        assert!(matches!(err, ImapMessageAppendStreamError::ShortMessage));
    }

    #[test]
    fn bye_returns_bye_error() {
        let mut append = ImapMessageAppendStream::new(
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
        let ImapMessageAppendStreamError::Bye(text) = err else {
            panic!("expected ImapMessageAppendStreamError::Bye, got {err:?}");
        };
        assert_eq!(text, "shutting down");
    }

    fn expect_wants_write(
        cor: &mut ImapMessageAppendStream,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> Vec<u8> {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapMessageAppendStreamYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(
        cor: &mut ImapMessageAppendStream,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapMessageAppendStreamYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_wants_stream(
        cor: &mut ImapMessageAppendStream,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapMessageAppendStreamYield::WantsStream) => {}
            state => panic!("expected WantsStream, got {state:?}"),
        }
    }

    fn expect_complete_ok(
        cor: &mut ImapMessageAppendStream,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapMessageAppendOutput {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Complete(Ok(value)) => value,
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut ImapMessageAppendStream,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapMessageAppendStreamError {
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
