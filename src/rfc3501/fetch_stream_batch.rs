//! IMAP batched FETCH body-stream coroutine: fetches the bodies of a whole
//! sequence set in **one** command and streams each straight to a per-message
//! sink, so N bodies cost one round trip instead of N.
//!
//! Sends `UID FETCH <set> (UID BODY.PEEK[])` (peek so syncing does not set
//! `\Seen`; `UID` so every returned body is self-identifying). The response is a
//! run of `* <seq> FETCH (UID <uid> BODY[] {len}\r\n<body>)` items followed by
//! the tagged status. The coroutine, per message, parses the header line for its
//! UID, announces it ([`MessageStart`](ImapMessageFetchStreamBatchYield::MessageStart)),
//! streams the body ([`BodyChunk`](ImapMessageFetchStreamBatchYield::BodyChunk) /
//! [`WantsStream`](ImapMessageFetchStreamBatchYield::WantsStream)), then closes it
//! ([`MessageEnd`](ImapMessageFetchStreamBatchYield::MessageEnd)) and moves to the
//! next — looping until the tagged response.
//!
//! The caller is expected to open a fresh sink at `MessageStart` and commit it at
//! `MessageEnd`; the body of the message in between is routed to that sink. A UID
//! requested but absent on the server simply never appears (fewer messages than
//! requested). If a body's FETCH line carries no parseable `UID` (a server that
//! ordered `UID` *after* the body literal — not seen in practice), the coroutine
//! fails with [`UidMissing`](ImapMessageFetchStreamBatchError::UidMissing) so the
//! caller can fall back to per-message fetches rather than misroute a body.

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
        sequence::SequenceSet,
    },
};
use log::{debug, trace};
use thiserror::Error;

use crate::coroutine::*;

/// Failure causes during the batched FETCH body-stream flow.
#[derive(Clone, Debug, Error)]
pub enum ImapMessageFetchStreamBatchError {
    /// The server rejected the command with a NO response.
    #[error("IMAP batched FETCH failed: NO {0}")]
    No(String),
    /// The server rejected the command with a BAD response.
    #[error("IMAP batched FETCH failed: BAD {0}")]
    Bad(String),
    /// The server closed the session with an untagged BYE.
    #[error("IMAP batched FETCH failed: BYE {0}")]
    Bye(String),
    /// The exchange ended without a tagged response from the server.
    #[error("IMAP batched FETCH failed: server did not return a tagged response")]
    MissingTagged,
    /// The socket reached EOF before a message's declared body octets were all
    /// streamed.
    #[error("IMAP batched FETCH failed: stream ended before the declared body length")]
    ShortBody,
    /// A body's FETCH line carried no parseable `UID`, so the body could not be
    /// attributed to a message. The caller should fall back to per-message
    /// fetches rather than risk misrouting.
    #[error("IMAP batched FETCH failed: FETCH body line without a parseable UID")]
    UidMissing,
}

/// Yield variants from the batched FETCH body-stream coroutine.
#[derive(Debug)]
pub enum ImapMessageFetchStreamBatchYield {
    /// The caller reads from its stream and resumes with the bytes.
    WantsRead,
    /// The caller writes the given bytes to its stream and resumes.
    WantsWrite(Vec<u8>),
    /// A new message's body is beginning; the caller opens a sink for `uid`. The
    /// following `BodyChunk` / `WantsStream` octets belong to it, until
    /// `MessageEnd`.
    MessageStart {
        /// The message's UID, parsed from its FETCH line.
        uid: u32,
    },
    /// Body octets the coroutine already read past the header line; the caller
    /// writes them to the current message's sink.
    BodyChunk(Vec<u8>),
    /// Read exactly `len` octets off the socket straight into the current
    /// message's sink; resume with `None` on success or `Some(&[])` if the socket
    /// ran short.
    WantsStream {
        /// Number of body octets left to stream for the current message.
        len: u32,
    },
    /// The current message's body is complete; the caller commits its sink.
    MessageEnd,
}

/// I/O-free IMAP batched FETCH coroutine streaming many message bodies from one
/// command.
pub struct ImapMessageFetchStreamBatch {
    state: State,
    command: Option<Vec<u8>>,
    pending: Vec<u8>,
    remaining: u32,
    stream_pending: bool,
    codec: ResponseCodec,
}

impl ImapMessageFetchStreamBatch {
    /// Builds a coroutine streaming the `BODY.PEEK[]` of every message in
    /// `sequence_set`; when `uid` is `true`, sends `UID FETCH`.
    pub fn new(sequence_set: SequenceSet, uid: bool) -> Self {
        let command = Command {
            tag: TagGenerator::new().generate(),
            body: CommandBody::Fetch {
                sequence_set,
                macro_or_item_names: MacroOrMessageDataItemNames::MessageDataItemNames(vec![
                    // NOTE: UID first so it lands on the header line, ahead of the
                    // body literal, and can be parsed before the body streams.
                    MessageDataItemName::Uid,
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

impl ImapCoroutine for ImapMessageFetchStreamBatch {
    type Yield = ImapMessageFetchStreamBatchYield;
    type Return = Result<(), ImapMessageFetchStreamBatchError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        mut arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        loop {
            match self.state {
                State::SendCommand => {
                    let command = self.command.take().expect("command sent once");
                    self.state = State::NextItem;
                    debug!("{}", self.state);
                    return ImapCoroutineState::Yielded(
                        ImapMessageFetchStreamBatchYield::WantsWrite(command),
                    );
                }
                // Between messages: parse lines until the next FETCH body header
                // (a new message) or the tagged status (done).
                State::NextItem => {
                    if let Some(bytes) = arg.take() {
                        if bytes.is_empty() {
                            let err = ImapMessageFetchStreamBatchError::MissingTagged;
                            return ImapCoroutineState::Complete(Err(err));
                        }
                        self.pending.extend_from_slice(bytes);
                    }

                    loop {
                        let Some(nl) = self.pending.iter().position(|&b| b == b'\n') else {
                            return ImapCoroutineState::Yielded(
                                ImapMessageFetchStreamBatchYield::WantsRead,
                            );
                        };

                        let line: Vec<u8> = self.pending.drain(..=nl).collect();
                        fragmentizer.enqueue_bytes(&line);

                        match fragmentizer.progress() {
                            // NOTE: a FETCH line announcing a body literal: parse
                            // its UID, start the message, stream the body next.
                            Some(FragmentInfo::Line {
                                announcement: Some(announcement),
                                ..
                            }) => {
                                let Some(uid) = parse_uid(&line) else {
                                    return ImapCoroutineState::Complete(Err(
                                        ImapMessageFetchStreamBatchError::UidMissing,
                                    ));
                                };
                                self.remaining = announcement.length;
                                self.state = State::Stream;
                                debug!("{}", self.state);
                                return ImapCoroutineState::Yielded(
                                    ImapMessageFetchStreamBatchYield::MessageStart { uid },
                                );
                            }
                            // NOTE: a complete line without literal: the tagged
                            // status (done), a BYE, or an untagged line we skip
                            // (the literal-closing `)`, stray untagged data).
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
                        // NOTE: drop the bypassed literal, close the message, and
                        // resume line parsing for the next item / tagged status.
                        fragmentizer.skip_message();
                        self.state = State::NextItem;
                        debug!("{}", self.state);
                        return ImapCoroutineState::Yielded(
                            ImapMessageFetchStreamBatchYield::MessageEnd,
                        );
                    }

                    if !self.pending.is_empty() {
                        let take = (self.remaining as usize).min(self.pending.len());
                        let chunk: Vec<u8> = self.pending.drain(..take).collect();
                        self.remaining -= take as u32;
                        return ImapCoroutineState::Yielded(
                            ImapMessageFetchStreamBatchYield::BodyChunk(chunk),
                        );
                    }

                    if self.stream_pending {
                        self.stream_pending = false;
                        if matches!(arg.take(), Some(&[])) {
                            let err = ImapMessageFetchStreamBatchError::ShortBody;
                            return ImapCoroutineState::Complete(Err(err));
                        }
                        self.remaining = 0;
                        continue;
                    }

                    self.stream_pending = true;
                    return ImapCoroutineState::Yielded(
                        ImapMessageFetchStreamBatchYield::WantsStream {
                            len: self.remaining,
                        },
                    );
                }
            }
        }
    }
}

impl ImapMessageFetchStreamBatch {
    /// Decodes the completed line in `fragmentizer`. Returns `Some` for a terminal
    /// tagged status or BYE; `None` for undecodable or untagged lines to skip (the
    /// literal-closing `)`, stray untagged data).
    fn decode_terminal(
        &self,
        fragmentizer: &Fragmentizer,
    ) -> Option<
        ImapCoroutineState<
            ImapMessageFetchStreamBatchYield,
            Result<(), ImapMessageFetchStreamBatchError>,
        >,
    > {
        match fragmentizer.decode_message(&self.codec) {
            Ok(Response::Status(Status::Tagged(tagged))) => {
                let text = tagged.body.text.to_string();
                let result = match tagged.body.kind {
                    StatusKind::Ok => Ok(()),
                    StatusKind::No => Err(ImapMessageFetchStreamBatchError::No(text)),
                    StatusKind::Bad => Err(ImapMessageFetchStreamBatchError::Bad(text)),
                };
                Some(ImapCoroutineState::Complete(result))
            }
            Ok(Response::Status(Status::Bye(bye))) => {
                let err = ImapMessageFetchStreamBatchError::Bye(bye.text.to_string());
                Some(ImapCoroutineState::Complete(Err(err)))
            }
            _ => None,
        }
    }
}

/// Extracts the `UID` value from a FETCH response line, e.g.
/// `* 12 FETCH (UID 34 BODY[] {1234}`. Scans for a `UID` token (word-boundary
/// left, whitespace + digits right); `None` when absent or unparseable.
fn parse_uid(line: &[u8]) -> Option<u32> {
    let mut i = 0;
    while i + 3 <= line.len() {
        let is_uid = line[i..i + 3].eq_ignore_ascii_case(b"UID");
        let boundary_left = i == 0 || !line[i - 1].is_ascii_alphanumeric();
        if is_uid && boundary_left {
            let mut j = i + 3;
            let mut saw_space = false;
            while j < line.len() && line[j] == b' ' {
                j += 1;
                saw_space = true;
            }
            let start = j;
            while j < line.len() && line[j].is_ascii_digit() {
                j += 1;
            }
            if saw_space && j > start {
                return core::str::from_utf8(&line[start..j]).ok()?.parse().ok();
            }
        }
        i += 1;
    }
    None
}

/// A convenience over [`ImapMessageFetchStreamBatch::new`] taking a single UID —
/// unused by the batch driver but handy in tests.
#[allow(dead_code)]
fn single(uid: NonZeroU32) -> ImapMessageFetchStreamBatch {
    ImapMessageFetchStreamBatch::new(SequenceSet::from(uid), true)
}

#[derive(Clone, Copy)]
enum State {
    SendCommand,
    NextItem,
    Stream,
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SendCommand => f.write_str("send batched fetch command"),
            Self::NextItem => f.write_str("parse next fetch item"),
            Self::Stream => f.write_str("stream body"),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::str;

    use alloc::{borrow::ToOwned, format, vec::Vec};

    use super::*;

    /// Drives the coroutine over a single canned reply, collecting `(uid, body)`
    /// pairs. Panics on any error.
    fn run_ok(cmd_set: &str, reply_after_tag: impl Fn(&str) -> String) -> Vec<(u32, Vec<u8>)> {
        let set: SequenceSet = cmd_set.try_into().unwrap();
        let mut cor = ImapMessageFetchStreamBatch::new(set, true);
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        // First resume writes the command; capture its tag.
        let cmd = match cor.resume(&mut frag, None) {
            ImapCoroutineState::Yielded(ImapMessageFetchStreamBatchYield::WantsWrite(b)) => b,
            s => panic!("expected WantsWrite, got {s:?}"),
        };
        let tag = str::from_utf8(&cmd)
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .to_owned();
        let reply = reply_after_tag(&tag);

        let mut out: Vec<(u32, Vec<u8>)> = Vec::new();
        let mut cur_uid: Option<u32> = None;
        let mut cur_body: Vec<u8> = Vec::new();
        let mut fed = false;
        let mut arg: Option<&[u8]> = None;
        let reply_bytes = reply.as_bytes();

        loop {
            match cor.resume(&mut frag, arg.take()) {
                ImapCoroutineState::Complete(Ok(())) => break,
                ImapCoroutineState::Complete(Err(e)) => panic!("unexpected error: {e:?}"),
                ImapCoroutineState::Yielded(ImapMessageFetchStreamBatchYield::WantsRead) => {
                    // Feed the whole reply on the first read, EOF-empty after.
                    arg = if !fed {
                        fed = true;
                        Some(reply_bytes)
                    } else {
                        Some(&[])
                    };
                }
                ImapCoroutineState::Yielded(ImapMessageFetchStreamBatchYield::WantsWrite(_)) => {}
                ImapCoroutineState::Yielded(ImapMessageFetchStreamBatchYield::MessageStart {
                    uid,
                }) => {
                    cur_uid = Some(uid);
                    cur_body.clear();
                }
                ImapCoroutineState::Yielded(ImapMessageFetchStreamBatchYield::BodyChunk(b)) => {
                    cur_body.extend_from_slice(&b);
                }
                ImapCoroutineState::Yielded(ImapMessageFetchStreamBatchYield::WantsStream {
                    ..
                }) => {
                    // The reply is fed in one go, so bodies always arrive as
                    // BodyChunk from pending; a WantsStream here means the test's
                    // canned reply was too fragmented — signal short.
                    arg = Some(&[]);
                }
                ImapCoroutineState::Yielded(ImapMessageFetchStreamBatchYield::MessageEnd) => {
                    out.push((cur_uid.take().unwrap(), core::mem::take(&mut cur_body)));
                }
            }
        }
        out
    }

    #[test]
    fn command_requests_uid_and_body_peek() {
        let set: SequenceSet = "1,2,3".try_into().unwrap();
        let mut cor = ImapMessageFetchStreamBatch::new(set, true);
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);
        let cmd = match cor.resume(&mut frag, None) {
            ImapCoroutineState::Yielded(ImapMessageFetchStreamBatchYield::WantsWrite(b)) => b,
            s => panic!("expected WantsWrite, got {s:?}"),
        };
        let line = str::from_utf8(&cmd).unwrap();
        // imap-codec collapses `1,2,3` to the range `1:3`.
        assert!(line.contains("UID FETCH 1:3 (UID BODY.PEEK[])"), "{line}");
    }

    #[test]
    fn streams_two_bodies_routed_by_uid() {
        let bodies = run_ok("10,11", |tag| {
            format!(
                "* 1 FETCH (UID 10 BODY[] {{5}}\r\nhello)\r\n\
                 * 2 FETCH (UID 11 BODY[] {{5}}\r\nworld)\r\n\
                 {tag} OK FETCH completed\r\n"
            )
        });
        assert_eq!(bodies.len(), 2);
        assert_eq!(bodies[0], (10, b"hello".to_vec()));
        assert_eq!(bodies[1], (11, b"world".to_vec()));
    }

    #[test]
    fn routes_by_uid_not_by_position() {
        // Server returns them in a different order than requested: routing must
        // follow the UID on each line, not arrival order.
        let bodies = run_ok("10,11", |tag| {
            format!(
                "* 2 FETCH (UID 11 BODY[] {{3}}\r\nBBB)\r\n\
                 * 1 FETCH (UID 10 BODY[] {{3}}\r\nAAA)\r\n\
                 {tag} OK done\r\n"
            )
        });
        assert_eq!(bodies, vec![(11, b"BBB".to_vec()), (10, b"AAA".to_vec())]);
    }

    #[test]
    fn skips_interleaved_untagged_and_missing_uids() {
        // A requested UID with no data simply never appears; an interleaved
        // untagged EXPUNGE between items is skipped.
        let bodies = run_ok("10,11,12", |tag| {
            format!(
                "* 1 FETCH (UID 10 BODY[] {{2}}\r\nhi)\r\n\
                 * 3 EXPUNGE\r\n\
                 * 4 FETCH (UID 12 BODY[] {{2}}\r\nyo)\r\n\
                 {tag} OK done\r\n"
            )
        });
        assert_eq!(bodies, vec![(10, b"hi".to_vec()), (12, b"yo".to_vec())]);
    }

    #[test]
    fn empty_result_completes_clean() {
        let bodies = run_ok("99", |tag| format!("{tag} OK nothing\r\n"));
        assert!(bodies.is_empty());
    }

    #[test]
    fn tagged_no_is_an_error() {
        let set: SequenceSet = "1".try_into().unwrap();
        let mut cor = ImapMessageFetchStreamBatch::new(set, true);
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);
        let cmd = match cor.resume(&mut frag, None) {
            ImapCoroutineState::Yielded(ImapMessageFetchStreamBatchYield::WantsWrite(b)) => b,
            s => panic!("{s:?}"),
        };
        let tag = str::from_utf8(&cmd)
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .to_owned();
        // WantsRead, then feed a NO.
        assert!(matches!(
            cor.resume(&mut frag, None),
            ImapCoroutineState::Yielded(ImapMessageFetchStreamBatchYield::WantsRead)
        ));
        let reply = format!("{tag} NO mailbox gone\r\n");
        match cor.resume(&mut frag, Some(reply.as_bytes())) {
            ImapCoroutineState::Complete(Err(ImapMessageFetchStreamBatchError::No(t))) => {
                assert_eq!(t, "mailbox gone")
            }
            s => panic!("expected No error, got {s:?}"),
        }
    }

    #[test]
    fn body_line_without_uid_errs_for_fallback() {
        // A body FETCH line whose UID we cannot parse must error (so the caller
        // falls back to per-message) rather than misroute the body.
        let set: SequenceSet = "1".try_into().unwrap();
        let mut cor = ImapMessageFetchStreamBatch::new(set, true);
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);
        let _ = cor.resume(&mut frag, None); // WantsWrite
        let _ = cor.resume(&mut frag, None); // WantsRead
        let reply = "* 1 FETCH (BODY[] {3}\r\nxxx)\r\nA1 OK done\r\n";
        match cor.resume(&mut frag, Some(reply.as_bytes())) {
            ImapCoroutineState::Complete(Err(ImapMessageFetchStreamBatchError::UidMissing)) => {}
            s => panic!("expected UidMissing, got {s:?}"),
        }
    }

    #[test]
    fn parse_uid_finds_the_token() {
        assert_eq!(parse_uid(b"* 12 FETCH (UID 34 BODY[] {5}\r\n"), Some(34));
        assert_eq!(
            parse_uid(b"* 1 FETCH (FLAGS (\\Seen) UID 7 BODY[] {2}\r\n"),
            Some(7)
        );
        assert_eq!(parse_uid(b"* 1 FETCH (BODY[] {2}\r\n"), None);
        // A "UID"-like substring in a word must not match (word boundary).
        assert_eq!(parse_uid(b"* 1 FETCH (XUID 9 BODY[] {2}\r\n"), None);
    }
}
