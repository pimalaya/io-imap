//! IMAP FETCH body-stream coroutine: fetches one message body and streams
//! it straight to the caller's sink instead of buffering it whole.
//!
//! Targets a single sequence number or UID and requests `BODY.PEEK[]` only
//! (peek so syncing does not set `\Seen`). The body literal bypasses the
//! [`Fragmentizer`] entirely: the coroutine feeds it the framing lines one
//! at a time, hands the announced octets to the caller via
//! [`ImapMessageFetchStreamYield::BodyChunk`] /
//! [`ImapMessageFetchStreamYield::WantsStream`], then resumes line parsing
//! for the tagged response.
//!
//! # Example
//!
//! ```rust,no_run
//! use core::num::NonZeroU32;
//! use std::{
//!     io::{self, Read, Write},
//!     net::TcpStream,
//! };
//!
//! use io_imap::{
//!     codec::fragmentizer::Fragmentizer,
//!     coroutine::{ImapCoroutine, ImapCoroutineState},
//!     rfc3501::fetch_stream::{
//!         ImapMessageFetchStream, ImapMessageFetchStreamYield,
//!     },
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negotiated, IMAP-authenticated)
//! let mut stream = TcpStream::connect("localhost:143").unwrap();
//!
//! let mut fragmentizer = Fragmentizer::new(50 * 1024 * 1024);
//! let mut buf = [0u8; 4096];
//! let mut sink = Vec::new();
//!
//! let id = NonZeroU32::new(42).unwrap();
//! let mut coroutine = ImapMessageFetchStream::new(id, true);
//! let mut arg = None;
//!
//! loop {
//!     match coroutine.resume(&mut fragmentizer, arg.take()) {
//!         ImapCoroutineState::Yielded(
//!             ImapMessageFetchStreamYield::WantsWrite(bytes),
//!         ) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         ImapCoroutineState::Yielded(
//!             ImapMessageFetchStreamYield::WantsRead,
//!         ) => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         ImapCoroutineState::Yielded(
//!             ImapMessageFetchStreamYield::BodyChunk(bytes),
//!         ) => {
//!             sink.write_all(&bytes).unwrap();
//!         }
//!         ImapCoroutineState::Yielded(
//!             ImapMessageFetchStreamYield::WantsStream { len },
//!         ) => {
//!             let mut body = (&mut stream).take(len as u64);
//!             io::copy(&mut body, &mut sink).unwrap();
//!         }
//!         ImapCoroutineState::Complete(Ok(())) => break,
//!         ImapCoroutineState::Complete(Err(err)) => panic!("{err}"),
//!     }
//! }
//!
//! println!("fetched {} body octets", sink.len());
//! ```

use core::{fmt, num::NonZeroU32};

use alloc::{string::String, string::ToString, vec, vec::Vec};

use imap_codec::{
    CommandCodec, ResponseCodec,
    encode::Encoder,
    fragmentizer::{FragmentInfo, Fragmentizer},
    imap_types::{
        command::{Command, CommandBody},
        core::TagGenerator,
        fetch::{MacroOrMessageDataItemNames, MessageDataItemName},
        response::{Response, Status, StatusKind},
        sequence::{SeqOrUid, SequenceSet},
    },
};
use log::{debug, trace};
use thiserror::Error;

use crate::coroutine::*;

/// Failure causes during the IMAP FETCH body-stream flow.
#[derive(Clone, Debug, Error)]
pub enum ImapMessageFetchStreamError {
    /// The server rejected the command with a NO response.
    #[error("IMAP FETCH failed: NO {0}")]
    No(String),
    /// The server rejected the command with a BAD response.
    #[error("IMAP FETCH failed: BAD {0}")]
    Bad(String),
    /// The server closed the session with an untagged BYE.
    #[error("IMAP FETCH failed: BYE {0}")]
    Bye(String),
    /// The exchange ended without a tagged response from the server.
    #[error("IMAP FETCH failed: server did not return a tagged response")]
    MissingTagged,
    /// The socket reached EOF before the declared body octets were all
    /// streamed.
    #[error("IMAP FETCH failed: stream ended before the declared body length")]
    ShortBody,
    /// A literal announcement appeared in the response trailer, where
    /// only plain lines are expected.
    #[error("IMAP FETCH failed: unexpected literal in response trailer")]
    UnexpectedLiteral,
}

/// Yield variants from the FETCH body-stream coroutine.
#[derive(Debug)]
pub enum ImapMessageFetchStreamYield {
    /// The caller reads from its stream and resumes with the bytes.
    WantsRead,
    /// The caller writes the given bytes to its stream and resumes.
    WantsWrite(Vec<u8>),
    /// Body octets the coroutine already read past the header line; the
    /// caller writes them to its sink.
    BodyChunk(Vec<u8>),
    /// Read exactly `len` octets off the socket straight into the sink;
    /// resume with `None` on success or `Some(&[])` if the socket ran short.
    WantsStream {
        /// Number of body octets left to stream.
        len: u32,
    },
}

/// I/O-free IMAP FETCH coroutine streaming one message body.
pub struct ImapMessageFetchStream {
    state: State,
    command: Option<Vec<u8>>,
    pending: Vec<u8>,
    remaining: u32,
    stream_pending: bool,
    codec: ResponseCodec,
}

impl ImapMessageFetchStream {
    /// Builds a FETCH coroutine streaming the `BODY.PEEK[]` of message
    /// `id`; when `uid` is `true`, sends `UID FETCH`.
    pub fn new(id: NonZeroU32, uid: bool) -> Self {
        let command = Command {
            tag: TagGenerator::new().generate(),
            body: CommandBody::Fetch {
                sequence_set: SequenceSet::from(SeqOrUid::from(id)),
                macro_or_item_names: MacroOrMessageDataItemNames::MessageDataItemNames(vec![
                    MessageDataItemName::BodyExt {
                        section: None,
                        partial: None,
                        peek: true,
                    },
                ]),
                uid,
                modifiers: Vec::new(),
            },
        };

        trace!("send IMAP command {command:?}");

        let command = CommandCodec::new().encode(&command).dump();

        Self {
            state: State::SendCommand,
            command: Some(command),
            pending: Vec::new(),
            remaining: 0,
            stream_pending: false,
            codec: ResponseCodec::new(),
        }
    }
}

impl ImapCoroutine for ImapMessageFetchStream {
    type Yield = ImapMessageFetchStreamYield;
    type Return = Result<(), ImapMessageFetchStreamError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        mut arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        loop {
            match self.state {
                State::SendCommand => {
                    let command = self.command.take().expect("command sent once");
                    self.state = State::Header;
                    debug!("{}", self.state);
                    return ImapCoroutineState::Yielded(ImapMessageFetchStreamYield::WantsWrite(
                        command,
                    ));
                }
                State::Header => {
                    if let Some(bytes) = arg.take() {
                        if bytes.is_empty() {
                            let err = ImapMessageFetchStreamError::MissingTagged;
                            return ImapCoroutineState::Complete(Err(err));
                        }
                        self.pending.extend_from_slice(bytes);
                    }

                    loop {
                        let Some(nl) = self.pending.iter().position(|&b| b == b'\n') else {
                            return ImapCoroutineState::Yielded(
                                ImapMessageFetchStreamYield::WantsRead,
                            );
                        };

                        let line: Vec<u8> = self.pending.drain(..=nl).collect();
                        fragmentizer.enqueue_bytes(&line);

                        match fragmentizer.progress() {
                            // NOTE: the FETCH line announces the body literal:
                            // take its length and stream the body next.
                            Some(FragmentInfo::Line {
                                announcement: Some(announcement),
                                ..
                            }) => {
                                self.remaining = announcement.length;
                                self.state = State::Stream;
                                debug!("{}", self.state);
                                break;
                            }
                            // NOTE: a complete line without literal: a tagged
                            // status (FETCH of a missing id returns OK with no
                            // body), a BYE, or an untagged response we ignore.
                            Some(FragmentInfo::Line {
                                announcement: None, ..
                            }) => {
                                if let Some(result) = self.decode_terminal(fragmentizer) {
                                    return result;
                                }
                            }
                            _ => {}
                        }
                    }
                }
                State::Stream => {
                    if self.remaining == 0 {
                        // NOTE: drop the bypassed literal and resume line
                        // parsing for the response trailer.
                        fragmentizer.skip_message();
                        self.state = State::Trailer;
                        debug!("{}", self.state);
                        continue;
                    }

                    if !self.pending.is_empty() {
                        let take = (self.remaining as usize).min(self.pending.len());
                        let chunk: Vec<u8> = self.pending.drain(..take).collect();
                        self.remaining -= take as u32;
                        return ImapCoroutineState::Yielded(
                            ImapMessageFetchStreamYield::BodyChunk(chunk),
                        );
                    }

                    if self.stream_pending {
                        self.stream_pending = false;
                        if matches!(arg.take(), Some(&[])) {
                            let err = ImapMessageFetchStreamError::ShortBody;
                            return ImapCoroutineState::Complete(Err(err));
                        }
                        self.remaining = 0;
                        continue;
                    }

                    self.stream_pending = true;
                    return ImapCoroutineState::Yielded(ImapMessageFetchStreamYield::WantsStream {
                        len: self.remaining,
                    });
                }
                State::Trailer => {
                    if let Some(bytes) = arg.take() {
                        if bytes.is_empty() {
                            let err = ImapMessageFetchStreamError::MissingTagged;
                            return ImapCoroutineState::Complete(Err(err));
                        }
                        self.pending.extend_from_slice(bytes);
                    }

                    loop {
                        let Some(nl) = self.pending.iter().position(|&b| b == b'\n') else {
                            return ImapCoroutineState::Yielded(
                                ImapMessageFetchStreamYield::WantsRead,
                            );
                        };

                        let line: Vec<u8> = self.pending.drain(..=nl).collect();
                        fragmentizer.enqueue_bytes(&line);

                        match fragmentizer.progress() {
                            Some(FragmentInfo::Line {
                                announcement: Some(_),
                                ..
                            }) => {
                                let err = ImapMessageFetchStreamError::UnexpectedLiteral;
                                return ImapCoroutineState::Complete(Err(err));
                            }
                            // NOTE: the literal close `)` and any other
                            // untagged line are skipped; only the tagged
                            // status and BYE terminate.
                            Some(FragmentInfo::Line {
                                announcement: None, ..
                            }) => {
                                if let Some(result) = self.decode_terminal(fragmentizer) {
                                    return result;
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }
}

impl ImapMessageFetchStream {
    /// Decodes the completed message in `fragmentizer`.
    ///
    /// Returns `Some` for a terminal tagged status or BYE; `None` for
    /// undecodable or untagged lines that should be skipped (the literal
    /// close `)`, stray untagged data).
    fn decode_terminal(
        &self,
        fragmentizer: &Fragmentizer,
    ) -> Option<
        ImapCoroutineState<ImapMessageFetchStreamYield, Result<(), ImapMessageFetchStreamError>>,
    > {
        match fragmentizer.decode_message(&self.codec) {
            Ok(Response::Status(Status::Tagged(tagged))) => {
                let text = tagged.body.text.to_string();
                let result = match tagged.body.kind {
                    StatusKind::Ok => Ok(()),
                    StatusKind::No => Err(ImapMessageFetchStreamError::No(text)),
                    StatusKind::Bad => Err(ImapMessageFetchStreamError::Bad(text)),
                };
                Some(ImapCoroutineState::Complete(result))
            }
            Ok(Response::Status(Status::Bye(bye))) => {
                let err = ImapMessageFetchStreamError::Bye(bye.text.to_string());
                Some(ImapCoroutineState::Complete(Err(err)))
            }
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
enum State {
    SendCommand,
    Header,
    Stream,
    Trailer,
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SendCommand => f.write_str("send fetch command"),
            Self::Header => f.write_str("parse fetch header"),
            Self::Stream => f.write_str("stream body"),
            Self::Trailer => f.write_str("parse fetch trailer"),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::str;

    use alloc::{borrow::ToOwned, format};

    use crate::rfc3501::fetch_stream::*;

    #[test]
    fn streams_body_in_one_read() {
        let mut cor = ImapMessageFetchStream::new(NonZeroU32::new(1).unwrap(), true);
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let cmd = expect_wants_write(&mut cor, &mut frag, None);
        let line = str::from_utf8(&cmd).expect("utf8 command");
        let tag = first_word(line).to_owned();
        assert!(line.contains("UID FETCH 1 BODY.PEEK[]"));

        expect_wants_read(&mut cor, &mut frag, None);

        // NOTE: header, whole body and trailer arrive together.
        let reply = format!("* 1 FETCH (BODY[] {{5}}\r\nhello)\r\n{tag} OK FETCH completed\r\n");
        let chunk = expect_body_chunk(&mut cor, &mut frag, Some(reply.as_bytes()));
        assert_eq!(chunk, b"hello");

        // NOTE: no socket bytes left to stream; the trailer completes
        // from pending.
        expect_complete_ok(&mut cor, &mut frag, None);
    }

    #[test]
    fn streams_body_via_wants_stream() {
        let mut cor = ImapMessageFetchStream::new(NonZeroU32::new(9).unwrap(), false);
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let cmd = expect_wants_write(&mut cor, &mut frag, None);
        let line = str::from_utf8(&cmd).expect("utf8 command");
        let tag = first_word(line).to_owned();
        assert!(line.contains("FETCH 9 BODY.PEEK[]"));
        assert!(!line.contains("UID"));

        expect_wants_read(&mut cor, &mut frag, None);

        // NOTE: only the header line arrives: the body must be streamed.
        let len = expect_wants_stream(&mut cor, &mut frag, Some(b"* 9 FETCH (BODY[] {12}\r\n"));
        assert_eq!(len, 12);

        // NOTE: the caller streamed all 12 octets: resume clean, then
        // read the trailer.
        expect_wants_read(&mut cor, &mut frag, None);

        let reply = format!(")\r\n{tag} OK FETCH completed\r\n");
        expect_complete_ok(&mut cor, &mut frag, Some(reply.as_bytes()));
    }

    #[test]
    fn partial_body_in_header_read_chunks_then_streams() {
        let mut cor = ImapMessageFetchStream::new(NonZeroU32::new(1).unwrap(), true);
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let cmd = expect_wants_write(&mut cor, &mut frag, None);
        let tag = first_word(str::from_utf8(&cmd).expect("utf8 command")).to_owned();

        expect_wants_read(&mut cor, &mut frag, None);

        // NOTE: header line plus the first 3 of 5 body octets.
        let chunk = expect_body_chunk(&mut cor, &mut frag, Some(b"* 1 FETCH (BODY[] {5}\r\nhel"));
        assert_eq!(chunk, b"hel");

        // NOTE: remaining 2 octets streamed off the socket.
        let len = expect_wants_stream(&mut cor, &mut frag, None);
        assert_eq!(len, 2);

        expect_wants_read(&mut cor, &mut frag, None);

        let reply = format!(")\r\n{tag} OK done\r\n");
        expect_complete_ok(&mut cor, &mut frag, Some(reply.as_bytes()));
    }

    #[test]
    fn missing_message_returns_ok_without_body() {
        let mut cor = ImapMessageFetchStream::new(NonZeroU32::new(7).unwrap(), true);
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let cmd = expect_wants_write(&mut cor, &mut frag, None);
        let tag = first_word(str::from_utf8(&cmd).expect("utf8 command")).to_owned();

        expect_wants_read(&mut cor, &mut frag, None);

        // NOTE: no untagged FETCH: the id did not exist.
        let reply = format!("{tag} OK FETCH completed\r\n");
        expect_complete_ok(&mut cor, &mut frag, Some(reply.as_bytes()));
    }

    #[test]
    fn tagged_no_returns_no_error() {
        let mut cor = ImapMessageFetchStream::new(NonZeroU32::new(7).unwrap(), true);
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let cmd = expect_wants_write(&mut cor, &mut frag, None);
        let tag = first_word(str::from_utf8(&cmd).expect("utf8 command")).to_owned();

        expect_wants_read(&mut cor, &mut frag, None);

        let reply = format!("{tag} NO mailbox not selected\r\n");
        let err = expect_complete_err(&mut cor, &mut frag, Some(reply.as_bytes()));
        let ImapMessageFetchStreamError::No(text) = err else {
            panic!("expected ImapMessageFetchStreamError::No, got {err:?}");
        };
        assert_eq!(text, "mailbox not selected");
    }

    #[test]
    fn short_stream_returns_short_body() {
        let mut cor = ImapMessageFetchStream::new(NonZeroU32::new(1).unwrap(), true);
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let _ = expect_wants_write(&mut cor, &mut frag, None);
        expect_wants_read(&mut cor, &mut frag, None);
        let _ = expect_wants_stream(&mut cor, &mut frag, Some(b"* 1 FETCH (BODY[] {12}\r\n"));

        // NOTE: socket EOF mid-body: the caller signals a short read.
        let err = expect_complete_err(&mut cor, &mut frag, Some(&[]));
        assert!(matches!(err, ImapMessageFetchStreamError::ShortBody));
    }

    fn expect_wants_write(
        cor: &mut ImapMessageFetchStream,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> Vec<u8> {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapMessageFetchStreamYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(
        cor: &mut ImapMessageFetchStream,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapMessageFetchStreamYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_body_chunk(
        cor: &mut ImapMessageFetchStream,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> Vec<u8> {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapMessageFetchStreamYield::BodyChunk(bytes)) => bytes,
            state => panic!("expected BodyChunk, got {state:?}"),
        }
    }

    fn expect_wants_stream(
        cor: &mut ImapMessageFetchStream,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> u32 {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapMessageFetchStreamYield::WantsStream { len }) => len,
            state => panic!("expected WantsStream, got {state:?}"),
        }
    }

    fn expect_complete_ok(
        cor: &mut ImapMessageFetchStream,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Complete(Ok(())) => {}
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut ImapMessageFetchStream,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapMessageFetchStreamError {
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
