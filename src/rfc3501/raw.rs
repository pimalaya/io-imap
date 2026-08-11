//! IMAP raw passthrough coroutine; writes one or more caller-tagged
//! command lines byte-for-byte and returns the verbatim server response.
//!
//! The input is sent to the server exactly as given: no tag is injected,
//! no CRLF is trimmed or appended. Callers are therefore responsible for
//! tagging every command and separating them with CRLF, which makes it
//! possible to pipeline a whole batch in a single exchange, e.g.
//!
//! ```text
//! a1 SELECT INBOX\r\na2 SEARCH ALL\r\na3 FETCH 1 BODY[]\r\n
//! ```
//!
//! Before anything hits the wire the input is parsed to extract the tag
//! of every command; the exchange then reads responses until *all* those
//! tags have been acknowledged by a matching tagged completion line. This
//! tolerates the server answering pipelined commands out of order (RFC
//! 3501 §5.5), which a "wait for the last tag" strategy would not.
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
//!     rfc3501::raw::ImapRaw,
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negotiated, IMAP-authenticated)
//! let mut stream = TcpStream::connect("localhost:143").unwrap();
//!
//! let mut fragmentizer = Fragmentizer::new(50 * 1024 * 1024);
//! let mut buf = [0u8; 4096];
//!
//! let mut coroutine = ImapRaw::new(b"a1 CAPABILITY\r\n").unwrap();
//! let mut arg = None;
//!
//! let response = loop {
//!     match coroutine.resume(&mut fragmentizer, arg.take()) {
//!         ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         ImapCoroutineState::Complete(Ok(response)) => break response,
//!         ImapCoroutineState::Complete(Err(err)) => panic!("{err}"),
//!     }
//! };
//!
//! println!("{response}");
//! ```

use core::{fmt, mem};

use alloc::{collections::BTreeSet, string::String, vec::Vec};

use imap_codec::{
    fragmentizer::{FragmentInfo, Fragmentizer},
    imap_types::utils::escape_byte_string,
};
use log::trace;
use thiserror::Error;

use crate::coroutine::*;

/// Upper bound on the size of a single parsed command, mirroring the
/// read-side fragmentizer cap.
const MAX_COMMAND_SIZE: u32 = 50 * 1024 * 1024;

/// Failure causes during the IMAP raw passthrough flow.
#[derive(Clone, Debug, Error)]
pub enum ImapRawError {
    /// The input carried no complete, tagged command.
    #[error("IMAP raw command failed: no tagged command in input")]
    NoCommand,
    /// A command line carried no valid tag (untagged `*`/`+` line, a bare
    /// word with no command, or otherwise malformed).
    #[error("IMAP raw command failed: a command line carries no valid tag")]
    MissingTag,
    /// The same tag was reused by more than one command in the batch,
    /// which would make its completion ambiguous.
    #[error("IMAP raw command failed: tag `{0}` is used by more than one command")]
    DuplicateTag(String),
    /// The final command was not terminated by CRLF (or a literal was
    /// truncated), so it would reach the server incomplete.
    #[error("IMAP raw command failed: the last command is not terminated")]
    IncompleteCommand,
    /// The stream reached EOF before every tagged completion line arrived.
    #[error("IMAP raw command failed: reached unexpected EOF on stream")]
    Eof,
}

/// I/O-free IMAP raw passthrough coroutine.
///
/// The returned String is a lossy UTF-8 decoding of the raw bytes, so binary
/// payloads carried in literals are rendered with replacement characters.
pub struct ImapRaw {
    command: Vec<u8>,
    pending: BTreeSet<Vec<u8>>,
    state: State,
    wants_read: bool,
    wants_write: Option<Vec<u8>>,
    response: Vec<u8>,
}

impl ImapRaw {
    /// Builds a raw passthrough over `command`, whose bytes are written to
    /// the server verbatim.
    ///
    /// The input must contain one or more IMAP commands, each carrying its
    /// own tag and terminated by CRLF; the tags are extracted up front so
    /// the exchange knows exactly how many tagged completions to wait for.
    /// Nothing is added to or stripped from the bytes sent on the wire.
    ///
    /// Returns an error when the input holds no tagged command, when a
    /// command carries no valid tag, when a tag is reused, or when the last
    /// command is not terminated.
    pub fn new(command: impl AsRef<[u8]>) -> Result<Self, ImapRawError> {
        let command = command.as_ref().to_vec();

        // NOTE: parse the outgoing bytes with the same fragmentizer the
        // read side uses, so tags are extracted correctly across literals
        // and CRLF-separated command boundaries.
        let mut probe = Fragmentizer::new(MAX_COMMAND_SIZE);
        probe.enqueue_bytes(&command);

        let mut pending = BTreeSet::new();

        while probe.progress().is_some() {
            if !probe.is_message_complete() {
                continue;
            }

            let tag = probe.decode_tag().ok_or(ImapRawError::MissingTag)?;
            let tag_bytes = tag.as_ref().as_bytes().to_vec();

            if !pending.insert(tag_bytes) {
                return Err(ImapRawError::DuplicateTag(String::from(tag.as_ref())));
            }
        }

        // NOTE: once the input is drained, a non-empty current message is a
        // trailing command that never reached its terminating CRLF.
        if !probe.message_bytes().is_empty() {
            return Err(ImapRawError::IncompleteCommand);
        }

        if pending.is_empty() {
            return Err(ImapRawError::NoCommand);
        }

        trace!(
            "build raw batch ({} command(s)): {}",
            pending.len(),
            escape_byte_string(&command),
        );

        Ok(Self {
            command,
            pending,
            state: State::Write,
            wants_read: false,
            wants_write: None,
            response: Vec::new(),
        })
    }
}

impl ImapCoroutine for ImapRaw {
    type Yield = ImapYield;
    type Return = Result<String, ImapRawError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        mut arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        loop {
            if let Some(bytes) = self.wants_write.take() {
                return ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes));
            }

            if mem::take(&mut self.wants_read) {
                return ImapCoroutineState::Yielded(ImapYield::WantsRead);
            }

            match self.state {
                State::Write => {
                    let line = mem::take(&mut self.command);
                    self.wants_write = Some(line);
                    self.state = State::Read;
                }
                State::Read => match arg.take() {
                    Some(&[]) => {
                        return ImapCoroutineState::Complete(Err(ImapRawError::Eof));
                    }
                    Some(data) => {
                        trace!("read bytes: {}", escape_byte_string(data));
                        fragmentizer.enqueue_bytes(data);
                        self.state = State::Deserialize;
                    }
                    None => {
                        self.wants_read = true;
                    }
                },
                State::Deserialize => match fragmentizer.progress() {
                    Some(FragmentInfo::Line { .. }) => {
                        if !fragmentizer.is_message_complete() {
                            continue;
                        }

                        let bytes = fragmentizer.message_bytes();
                        trace!("captured response message: {}", escape_byte_string(bytes));
                        self.response.extend_from_slice(bytes);

                        // NOTE: untagged responses decode to no tag and are
                        // captured then ignored; a tagged completion clears
                        // the matching command from the pending set.
                        if let Some(tag) = fragmentizer.decode_tag() {
                            self.pending.remove(tag.as_ref().as_bytes());
                        }
                    }
                    Some(FragmentInfo::Literal { .. }) => {
                        // NOTE: literal bytes belong to the current message;
                        // they are captured wholesale once its final line
                        // completes.
                    }
                    None if self.pending.is_empty() => {
                        let response = String::from_utf8_lossy(&self.response).into_owned();
                        trace!("raw response complete ({} bytes)", self.response.len());
                        return ImapCoroutineState::Complete(Ok(response));
                    }
                    None => {
                        self.state = State::Read;
                    }
                },
            }
        }
    }
}

enum State {
    Write,
    Read,
    Deserialize,
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Write => f.write_str("write raw command"),
            Self::Read => f.write_str("read response"),
            Self::Deserialize => f.write_str("deserialize response"),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::format;

    use crate::rfc3501::raw::*;

    #[test]
    fn command_is_written_verbatim() {
        let input = b"a1 CAPABILITY\r\n";
        let mut raw = ImapRaw::new(input).unwrap();
        let mut frag = Fragmentizer::new(MAX_COMMAND_SIZE);

        let bytes = expect_wants_write(&mut raw, &mut frag, None);
        assert_eq!(bytes, input);
    }

    #[test]
    fn success_returns_full_raw_response() {
        let mut raw = ImapRaw::new(b"a1 CAPABILITY\r\n").unwrap();
        let mut frag = Fragmentizer::new(MAX_COMMAND_SIZE);

        let _ = expect_wants_write(&mut raw, &mut frag, None);
        expect_wants_read(&mut raw, &mut frag);

        let reply = "* CAPABILITY IMAP4REV1 IDLE\r\na1 OK CAPABILITY completed\r\n";
        let out = expect_complete_ok(&mut raw, &mut frag, reply.as_bytes());
        assert_eq!(out, reply);
    }

    #[test]
    fn batch_waits_for_every_tag_out_of_order() {
        let input = b"a1 SELECT INBOX\r\na2 CAPABILITY\r\n";
        let mut raw = ImapRaw::new(input).unwrap();
        let mut frag = Fragmentizer::new(MAX_COMMAND_SIZE);

        let bytes = expect_wants_write(&mut raw, &mut frag, None);
        assert_eq!(bytes, input);

        expect_wants_read(&mut raw, &mut frag);

        // Server answers the second command before the first.
        let first = "* CAPABILITY IMAP4REV1\r\na2 OK CAPABILITY completed\r\n";
        expect_wants_read_after(&mut raw, &mut frag, first.as_bytes());

        let second = "* 3 EXISTS\r\na1 OK [READ-WRITE] SELECT completed\r\n";
        let out = expect_complete_ok(&mut raw, &mut frag, second.as_bytes());
        assert_eq!(out, format!("{first}{second}"));
    }

    #[test]
    fn tagged_no_is_returned_as_payload_not_error() {
        let mut raw = ImapRaw::new(b"a1 SELECT INBOX\r\n").unwrap();
        let mut frag = Fragmentizer::new(MAX_COMMAND_SIZE);

        let _ = expect_wants_write(&mut raw, &mut frag, None);
        expect_wants_read(&mut raw, &mut frag);

        let reply = "a1 NO mailbox does not exist\r\n";
        let out = expect_complete_ok(&mut raw, &mut frag, reply.as_bytes());
        assert_eq!(out, reply);
        assert!(out.contains("NO mailbox does not exist"));
    }

    #[test]
    fn response_with_literal_is_captured_verbatim() {
        let mut raw = ImapRaw::new(b"a1 FETCH 1 BODY[]\r\n").unwrap();
        let mut frag = Fragmentizer::new(MAX_COMMAND_SIZE);

        let _ = expect_wants_write(&mut raw, &mut frag, None);
        expect_wants_read(&mut raw, &mut frag);

        let reply = "* 1 FETCH (BODY[] {3}\r\nabc)\r\na1 OK FETCH completed\r\n";
        let out = expect_complete_ok(&mut raw, &mut frag, reply.as_bytes());
        assert_eq!(out, reply);
        assert!(out.contains("abc"));
    }

    #[test]
    fn command_with_literal_is_parsed_for_its_tag() {
        // The command itself spans a synchronizing literal; its single tag
        // must still be extracted so exactly one completion is awaited.
        let input = b"a1 LOGIN {5}\r\nADMIN {5}\r\nsesam\r\n";
        let raw = ImapRaw::new(input).unwrap();
        assert_eq!(raw.pending.len(), 1);
        assert!(raw.pending.contains(b"a1".as_slice()));
    }

    #[test]
    fn missing_tag_is_rejected() {
        let err = expect_new_err(b"CAPABILITY\r\n");
        assert!(matches!(err, ImapRawError::MissingTag));
    }

    #[test]
    fn duplicate_tag_is_rejected() {
        let err = expect_new_err(b"a1 NOOP\r\na1 NOOP\r\n");
        assert!(matches!(err, ImapRawError::DuplicateTag(tag) if tag == "a1"));
    }

    #[test]
    fn unterminated_command_is_rejected() {
        let err = expect_new_err(b"a1 CAPABILITY");
        assert!(matches!(err, ImapRawError::IncompleteCommand));
    }

    #[test]
    fn empty_input_is_rejected() {
        let err = expect_new_err(b"");
        assert!(matches!(err, ImapRawError::NoCommand));
    }

    fn expect_new_err(command: &[u8]) -> ImapRawError {
        match ImapRaw::new(command) {
            Ok(_) => panic!("expected ImapRaw::new to fail"),
            Err(err) => err,
        }
    }

    #[test]
    fn eof_before_tagged_returns_error() {
        let mut raw = ImapRaw::new(b"a1 CAPABILITY\r\n").unwrap();
        let mut frag = Fragmentizer::new(MAX_COMMAND_SIZE);

        let _ = expect_wants_write(&mut raw, &mut frag, None);
        expect_wants_read(&mut raw, &mut frag);

        let err = expect_complete_err(&mut raw, &mut frag, b"");
        assert!(matches!(err, ImapRawError::Eof));
    }

    fn expect_wants_write(
        cor: &mut ImapRaw,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> Vec<u8> {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ImapRaw, frag: &mut Fragmentizer) {
        match cor.resume(frag, None) {
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_wants_read_after(cor: &mut ImapRaw, frag: &mut Fragmentizer, reply: &[u8]) {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(cor: &mut ImapRaw, frag: &mut Fragmentizer, reply: &[u8]) -> String {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Complete(Ok(value)) => value,
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut ImapRaw,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> ImapRawError {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        }
    }
}
