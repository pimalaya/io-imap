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
//!     codec::{fragmentizer::Fragmentizer, imap_types::core::TagGenerator},
//!     coroutine::{ImapCoroutine, ImapCoroutineState},
//!     rfc3501::fetch_stream::{
//!         ImapMessageFetchStream, ImapMessageFetchStreamOptions,
//!         ImapMessageFetchStreamYield,
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
//! let opts = ImapMessageFetchStreamOptions {
//!     uid: true,
//!     ..Default::default()
//! };
//! let mut coroutine = ImapMessageFetchStream::new(id, opts);
//! let mut tags = TagGenerator::new();
//! let mut tag;
//! let mut arg = None;
//!
//! loop {
//!     match coroutine.resume(&mut fragmentizer, arg.take()) {
//!         ImapCoroutineState::Yielded(ImapMessageFetchStreamYield::WantsTag) => {
//!             tag = tags.generate();
//!             arg = Some(tag.as_ref().as_bytes());
//!         }
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

use core::{fmt, mem, num::NonZeroU32};

use alloc::{string::String, string::ToString, vec, vec::Vec};

use imap_codec::{
    CommandCodec, ResponseCodec,
    encode::Encoder,
    fragmentizer::{FragmentInfo, Fragmentizer},
    imap_types::{
        IntoStatic,
        command::{Command, CommandBody},
        core::Tag,
        error::ValidationError,
        fetch::{MacroOrMessageDataItemNames, MessageDataItemName},
        response::StatusKind,
        sequence::{SeqOrUid, SequenceSet},
    },
};
use log::{debug, trace};
use thiserror::Error;

use crate::{
    coroutine::*,
    rfc3501::fetch_stream_batch::DEFAULT_MAX_LITERAL_LEN,
    send::{ImapCompletion, decode_completion},
};

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
    /// The caller resumed a `WantsTag` without a tag.
    #[error("IMAP FETCH failed: missing command tag")]
    MissingTag,
    /// The caller resumed a `WantsTag` with bytes that are not a valid
    /// IMAP tag.
    #[error("IMAP FETCH failed: invalid command tag")]
    InvalidTag(#[source] ValidationError),
    /// The socket reached EOF before the declared body octets were all
    /// streamed.
    #[error("IMAP FETCH failed: stream ended before the declared body length")]
    ShortBody,
    /// A literal announcement appeared in the response trailer, where
    /// only plain lines are expected.
    #[error("IMAP FETCH failed: unexpected literal in response trailer")]
    UnexpectedLiteral,
    /// A response line ran past the given number of octets.
    #[error("IMAP FETCH failed: response line longer than {0} octets")]
    LineTooLong(usize),
    /// The body announced more octets than its declared size or the
    /// [`max_literal_len`](ImapMessageFetchStreamOptions::max_literal_len).
    #[error("IMAP FETCH failed: body announces {len} octets, over {max}")]
    LiteralTooLong {
        /// The announced body length.
        len: u32,
        /// The largest length accepted for this body.
        max: u32,
    },
}

/// Options for [`ImapMessageFetchStream::new`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImapMessageFetchStreamOptions {
    /// Sends `UID FETCH` instead of `FETCH`.
    pub uid: bool,
    /// Largest body accepted, in octets; [`DEFAULT_MAX_LITERAL_LEN`] by
    /// default.
    pub max_literal_len: u32,
    /// Body size declared by the caller, e.g. from `RFC822.SIZE`.
    ///
    /// A body announcing more octets fails, so a caller facing servers
    /// that miscount pads this size.
    pub size: Option<u32>,
}

impl Default for ImapMessageFetchStreamOptions {
    fn default() -> Self {
        Self {
            uid: false,
            max_literal_len: DEFAULT_MAX_LITERAL_LEN,
            size: None,
        }
    }
}

/// Yield variants from the FETCH body-stream coroutine.
#[derive(Debug)]
pub enum ImapMessageFetchStreamYield {
    /// The caller resumes with the tag of the FETCH command.
    WantsTag,
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

/// Longest response line accepted around the body, in octets.
const MAX_LINE_LEN: usize = 1024 * 1024;

/// I/O-free IMAP FETCH coroutine streaming one message body.
pub struct ImapMessageFetchStream {
    state: State,
    body: Option<CommandBody<'static>>,
    tag_requested: bool,
    tag: Option<Tag<'static>>,
    pending: Vec<u8>,
    scanned: usize,
    remaining: u32,
    stream_pending: bool,
    codec: ResponseCodec,
    max_literal_len: u32,
}

impl ImapMessageFetchStream {
    /// Builds a FETCH coroutine streaming the `BODY.PEEK[]` of message
    /// `id`.
    pub fn new(id: NonZeroU32, opts: ImapMessageFetchStreamOptions) -> Self {
        let body = CommandBody::Fetch {
            sequence_set: SequenceSet::from(SeqOrUid::from(id)),
            macro_or_item_names: MacroOrMessageDataItemNames::MessageDataItemNames(vec![
                MessageDataItemName::BodyExt {
                    section: None,
                    partial: None,
                    peek: true,
                },
            ]),
            uid: opts.uid,
            modifiers: Vec::new(),
        };

        trace!("send IMAP command {body:?}");

        let max_literal_len = match opts.size {
            Some(size) => size.min(opts.max_literal_len),
            None => opts.max_literal_len,
        };

        Self {
            state: State::SendCommand,
            body: Some(body),
            tag_requested: false,
            tag: None,
            pending: Vec::new(),
            scanned: 0,
            remaining: 0,
            stream_pending: false,
            codec: ResponseCodec::new(),
            max_literal_len,
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
                State::SendCommand => match arg.take() {
                    Some(bytes) => {
                        let tag = match Tag::try_from(bytes) {
                            Ok(tag) => tag.into_static(),
                            Err(err) => {
                                let err = ImapMessageFetchStreamError::InvalidTag(err);
                                return ImapCoroutineState::Complete(Err(err));
                            }
                        };

                        self.tag = Some(tag.clone());

                        let body = self.body.take().expect("command tagged once");
                        let command = CommandCodec::new().encode(&Command { tag, body }).dump();

                        self.state = State::Header;
                        debug!("{}", self.state);

                        let yielded = ImapMessageFetchStreamYield::WantsWrite(command);
                        return ImapCoroutineState::Yielded(yielded);
                    }
                    None if self.tag_requested => {
                        let err = ImapMessageFetchStreamError::MissingTag;
                        return ImapCoroutineState::Complete(Err(err));
                    }
                    None => {
                        self.tag_requested = true;
                        return ImapCoroutineState::Yielded(ImapMessageFetchStreamYield::WantsTag);
                    }
                },
                State::Header => {
                    if let Some(bytes) = arg.take() {
                        if bytes.is_empty() {
                            let err = ImapMessageFetchStreamError::MissingTagged;
                            return ImapCoroutineState::Complete(Err(err));
                        }
                        self.pending.extend_from_slice(bytes);
                    }

                    loop {
                        let line = match self.next_line() {
                            Ok(Some(line)) => line,
                            Ok(None) => {
                                return ImapCoroutineState::Yielded(
                                    ImapMessageFetchStreamYield::WantsRead,
                                );
                            }
                            Err(err) => return ImapCoroutineState::Complete(Err(err)),
                        };
                        fragmentizer.enqueue_bytes(&line);

                        match fragmentizer.progress() {
                            // NOTE: the FETCH line announces the body literal:
                            // take its length and stream the body next.
                            Some(FragmentInfo::Line {
                                announcement: Some(announcement),
                                ..
                            }) => {
                                if announcement.length > self.max_literal_len {
                                    let err = ImapMessageFetchStreamError::LiteralTooLong {
                                        len: announcement.length,
                                        max: self.max_literal_len,
                                    };
                                    return ImapCoroutineState::Complete(Err(err));
                                }

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
                        let line = match self.next_line() {
                            Ok(Some(line)) => line,
                            Ok(None) => {
                                return ImapCoroutineState::Yielded(
                                    ImapMessageFetchStreamYield::WantsRead,
                                );
                            }
                            Err(err) => return ImapCoroutineState::Complete(Err(err)),
                        };
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
    /// Takes the next complete line off the pending octets, `None` when
    /// more must be read.
    ///
    /// Only the octets not yet scanned are searched, and a line is capped,
    /// so an endless line costs neither quadratic time nor unbounded memory.
    fn next_line(&mut self) -> Result<Option<Vec<u8>>, ImapMessageFetchStreamError> {
        let unscanned = &self.pending[self.scanned..];

        let Some(pos) = unscanned.iter().position(|&b| b == b'\n') else {
            self.scanned = self.pending.len();

            if self.scanned > MAX_LINE_LEN {
                return Err(ImapMessageFetchStreamError::LineTooLong(MAX_LINE_LEN));
            }

            return Ok(None);
        };

        let nl = self.scanned + pos;
        self.scanned = 0;

        if nl >= MAX_LINE_LEN {
            return Err(ImapMessageFetchStreamError::LineTooLong(MAX_LINE_LEN));
        }

        Ok(Some(self.pending.drain(..=nl).collect()))
    }

    /// Decodes the completed message in `fragmentizer`.
    ///
    /// Returns `Some` for the tagged status of the command or a BYE;
    /// `None` for the lines to skip (the literal close `)`, untagged
    /// data, the completion of another command).
    fn decode_terminal(
        &mut self,
        fragmentizer: &mut Fragmentizer,
    ) -> Option<
        ImapCoroutineState<ImapMessageFetchStreamYield, Result<(), ImapMessageFetchStreamError>>,
    > {
        let result = match decode_completion(fragmentizer, &self.codec, self.tag.as_ref()?)? {
            ImapCompletion::Tagged(tagged) => {
                let text = tagged.body.text.to_string();

                match tagged.body.kind {
                    StatusKind::Ok => Ok(()),
                    StatusKind::No => Err(ImapMessageFetchStreamError::No(text)),
                    StatusKind::Bad => Err(ImapMessageFetchStreamError::Bad(text)),
                }
            }
            ImapCompletion::Bye(bye) => Err(ImapMessageFetchStreamError::Bye(bye.text.to_string())),
        };

        // NOTE: what was read past the end belongs to the next exchange.
        fragmentizer.enqueue_bytes(&mem::take(&mut self.pending));

        Some(ImapCoroutineState::Complete(result))
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
        let mut cor = ImapMessageFetchStream::new(NonZeroU32::new(1).unwrap(), uid_opts());
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        expect_wants_tag(&mut cor, &mut frag);
        let cmd = expect_wants_write(&mut cor, &mut frag, Some(b"A1"));
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
        let mut cor = ImapMessageFetchStream::new(NonZeroU32::new(9).unwrap(), Default::default());
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        expect_wants_tag(&mut cor, &mut frag);
        let cmd = expect_wants_write(&mut cor, &mut frag, Some(b"A1"));
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
        let mut cor = ImapMessageFetchStream::new(NonZeroU32::new(1).unwrap(), uid_opts());
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        expect_wants_tag(&mut cor, &mut frag);
        let cmd = expect_wants_write(&mut cor, &mut frag, Some(b"A1"));
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
        let mut cor = ImapMessageFetchStream::new(NonZeroU32::new(7).unwrap(), uid_opts());
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        expect_wants_tag(&mut cor, &mut frag);
        let cmd = expect_wants_write(&mut cor, &mut frag, Some(b"A1"));
        let tag = first_word(str::from_utf8(&cmd).expect("utf8 command")).to_owned();

        expect_wants_read(&mut cor, &mut frag, None);

        // NOTE: no untagged FETCH: the id did not exist.
        let reply = format!("{tag} OK FETCH completed\r\n");
        expect_complete_ok(&mut cor, &mut frag, Some(reply.as_bytes()));
    }

    #[test]
    fn tagged_no_returns_no_error() {
        let mut cor = ImapMessageFetchStream::new(NonZeroU32::new(7).unwrap(), uid_opts());
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        expect_wants_tag(&mut cor, &mut frag);
        let cmd = expect_wants_write(&mut cor, &mut frag, Some(b"A1"));
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
        let mut cor = ImapMessageFetchStream::new(NonZeroU32::new(1).unwrap(), uid_opts());
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        expect_wants_tag(&mut cor, &mut frag);
        let _ = expect_wants_write(&mut cor, &mut frag, Some(b"A1"));
        expect_wants_read(&mut cor, &mut frag, None);
        let _ = expect_wants_stream(&mut cor, &mut frag, Some(b"* 1 FETCH (BODY[] {12}\r\n"));

        // NOTE: socket EOF mid-body: the caller signals a short read.
        let err = expect_complete_err(&mut cor, &mut frag, Some(&[]));
        assert!(matches!(err, ImapMessageFetchStreamError::ShortBody));
    }

    #[test]
    fn endless_line_fails_past_the_cap() {
        let mut cor = ImapMessageFetchStream::new(NonZeroU32::new(1).unwrap(), uid_opts());
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);
        let chunk = [b'x'; 64 * 1024];

        expect_wants_tag(&mut cor, &mut frag);
        let _ = expect_wants_write(&mut cor, &mut frag, Some(b"A1"));
        expect_wants_read(&mut cor, &mut frag, None);

        for _ in 0..MAX_LINE_LEN / chunk.len() {
            expect_wants_read(&mut cor, &mut frag, Some(&chunk));
        }

        let err = expect_complete_err(&mut cor, &mut frag, Some(&chunk));
        assert!(matches!(
            err,
            ImapMessageFetchStreamError::LineTooLong(MAX_LINE_LEN)
        ));
    }

    #[test]
    fn line_split_across_reads_is_found() {
        let mut cor = ImapMessageFetchStream::new(NonZeroU32::new(1).unwrap(), uid_opts());
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        expect_wants_tag(&mut cor, &mut frag);
        let cmd = expect_wants_write(&mut cor, &mut frag, Some(b"A1"));
        let tag = first_word(str::from_utf8(&cmd).expect("utf8 command")).to_owned();

        expect_wants_read(&mut cor, &mut frag, None);
        expect_wants_read(&mut cor, &mut frag, Some(b"* 1 FETCH (BO"));

        let chunk = expect_body_chunk(&mut cor, &mut frag, Some(b"DY[] {2}\r\nhi"));
        assert_eq!(chunk, b"hi");

        expect_wants_read(&mut cor, &mut frag, None);
        expect_wants_read(&mut cor, &mut frag, Some(b")\r\n"));

        let reply = format!("{tag} OK done\r\n");
        expect_complete_ok(&mut cor, &mut frag, Some(reply.as_bytes()));
    }

    #[test]
    fn literal_over_max_fails() {
        let mut cor = ImapMessageFetchStream::new(NonZeroU32::new(1).unwrap(), uid_opts());
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        expect_wants_tag(&mut cor, &mut frag);
        let _ = expect_wants_write(&mut cor, &mut frag, Some(b"A1"));
        expect_wants_read(&mut cor, &mut frag, None);

        let header = b"* 1 FETCH (BODY[] {4294967295}\r\n";
        let err = expect_complete_err(&mut cor, &mut frag, Some(header));
        let ImapMessageFetchStreamError::LiteralTooLong { len, max } = err else {
            panic!("expected LiteralTooLong, got {err:?}");
        };
        assert_eq!((len, max), (4294967295, DEFAULT_MAX_LITERAL_LEN));
    }

    #[test]
    fn foreign_completion_is_skipped() {
        let mut cor = ImapMessageFetchStream::new(NonZeroU32::new(1).unwrap(), uid_opts());
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        expect_wants_tag(&mut cor, &mut frag);
        let _ = expect_wants_write(&mut cor, &mut frag, Some(b"A1"));
        expect_wants_read(&mut cor, &mut frag, None);
        expect_wants_read(&mut cor, &mut frag, Some(b"B9 OK stale\r\n"));

        let err = expect_complete_err(&mut cor, &mut frag, Some(b"A1 NO gone\r\n"));
        assert!(matches!(err, ImapMessageFetchStreamError::No(text) if text == "gone"));
    }

    #[test]
    fn completion_holding_8bit_text_is_read() {
        let mut cor = ImapMessageFetchStream::new(NonZeroU32::new(1).unwrap(), uid_opts());
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        expect_wants_tag(&mut cor, &mut frag);
        let _ = expect_wants_write(&mut cor, &mut frag, Some(b"A1"));
        expect_wants_read(&mut cor, &mut frag, None);

        let reply = "A1 NO Mailbox doesn't exist: Été\r\n";
        let err = expect_complete_err(&mut cor, &mut frag, Some(reply.as_bytes()));
        assert!(matches!(err, ImapMessageFetchStreamError::No(text) if text.ends_with("??t??")));
    }

    #[test]
    fn bytes_past_completion_return_to_fragmentizer() {
        let mut cor = ImapMessageFetchStream::new(NonZeroU32::new(1).unwrap(), uid_opts());
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        expect_wants_tag(&mut cor, &mut frag);
        let _ = expect_wants_write(&mut cor, &mut frag, Some(b"A1"));
        expect_wants_read(&mut cor, &mut frag, None);
        expect_complete_ok(&mut cor, &mut frag, Some(b"A1 OK done\r\n* BYE bye\r\n"));

        assert!(frag.progress().is_some());
        assert_eq!(b"* BYE bye\r\n", frag.message_bytes());
    }

    #[test]
    fn literal_over_declared_size_fails() {
        let opts = ImapMessageFetchStreamOptions {
            size: Some(4),
            ..uid_opts()
        };
        let mut cor = ImapMessageFetchStream::new(NonZeroU32::new(1).unwrap(), opts);
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        expect_wants_tag(&mut cor, &mut frag);
        let _ = expect_wants_write(&mut cor, &mut frag, Some(b"A1"));
        expect_wants_read(&mut cor, &mut frag, None);

        let header = b"* 1 FETCH (BODY[] {5}\r\nhello)\r\n";
        let err = expect_complete_err(&mut cor, &mut frag, Some(header));
        let ImapMessageFetchStreamError::LiteralTooLong { len, max } = err else {
            panic!("expected LiteralTooLong, got {err:?}");
        };
        assert_eq!((len, max), (5, 4));
    }

    fn uid_opts() -> ImapMessageFetchStreamOptions {
        ImapMessageFetchStreamOptions {
            uid: true,
            ..Default::default()
        }
    }

    fn expect_wants_tag(cor: &mut ImapMessageFetchStream, frag: &mut Fragmentizer) {
        match cor.resume(frag, None) {
            ImapCoroutineState::Yielded(ImapMessageFetchStreamYield::WantsTag) => {}
            state => panic!("expected WantsTag, got {state:?}"),
        }
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
