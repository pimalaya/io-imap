//! IMAP raw passthrough coroutine; sends an arbitrary command line and
//! returns the verbatim server response.
//!
//! The input is a command WITHOUT tag and WITHOUT trailing CRLF (e.g.
//! `SEARCH FROM "foo@bar"` or `CAPABILITY`); the coroutine prepends a
//! generated tag and appends CRLF, then reads every response up to and
//! including the tagged completion line matching that tag. Synchronizing
//! literals (`{n}` continuation requests) are out of scope.
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
//! let mut coroutine = ImapRaw::new("CAPABILITY");
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

use alloc::{string::String, vec::Vec};

use imap_codec::{
    fragmentizer::{FragmentInfo, Fragmentizer},
    imap_types::{core::TagGenerator, utils::escape_byte_string},
};
use log::trace;
use thiserror::Error;

use crate::coroutine::*;

/// Failure causes during the IMAP raw passthrough flow.
#[derive(Clone, Debug, Error)]
pub enum ImapRawError {
    /// The stream reached EOF before the tagged completion line arrived.
    #[error("IMAP raw command failed: reached unexpected EOF on stream")]
    Eof,
}

/// I/O-free IMAP raw passthrough coroutine.
///
/// The returned String is a lossy UTF-8 decoding of the raw bytes, so binary
/// payloads carried in literals are rendered with replacement characters.
pub struct ImapRaw {
    tag_bytes: Vec<u8>,
    command: Vec<u8>,
    state: State,
    wants_read: bool,
    wants_write: Option<Vec<u8>>,
    response: Vec<u8>,
    done: bool,
}

impl ImapRaw {
    /// Builds the wire line `<tag> <command>\r\n` around a freshly
    /// generated tag.
    ///
    /// A trailing CRLF on `command` is trimmed so callers cannot
    /// accidentally emit an empty extra line.
    pub fn new(command: impl AsRef<str>) -> Self {
        let tag = TagGenerator::new().generate();
        let tag_bytes = tag.as_ref().as_bytes().to_vec();

        let command = command.as_ref().trim_end_matches(['\r', '\n']);

        let mut line = Vec::with_capacity(tag_bytes.len() + command.len() + 3);
        line.extend_from_slice(&tag_bytes);
        line.push(b' ');
        line.extend_from_slice(command.as_bytes());
        line.extend_from_slice(b"\r\n");

        trace!("build raw command: {}", escape_byte_string(&line));

        Self {
            tag_bytes,
            command: line,
            state: State::Write,
            wants_read: false,
            wants_write: None,
            response: Vec::new(),
            done: false,
        }
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

                        // NOTE: the only tagged response in a single-command
                        // exchange is our completion line; an untagged
                        // response decodes to no tag and is captured then
                        // skipped.
                        let is_completion = fragmentizer
                            .decode_tag()
                            .is_some_and(|tag| tag.as_ref().as_bytes() == self.tag_bytes);

                        if is_completion {
                            self.done = true;
                        }
                    }
                    Some(FragmentInfo::Literal { .. }) => {
                        // NOTE: literal bytes belong to the current message;
                        // they are captured wholesale once its final line
                        // completes.
                    }
                    None if self.done => {
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
    use core::str;

    use alloc::format;

    use crate::rfc3501::raw::*;

    #[test]
    fn success_returns_full_raw_response() {
        let mut raw = ImapRaw::new("CAPABILITY");
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut raw, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command"));

        expect_wants_read(&mut raw, &mut frag);

        let reply = format!("* CAPABILITY IMAP4REV1 IDLE\r\n{tag} OK CAPABILITY completed\r\n");
        let out = expect_complete_ok(&mut raw, &mut frag, reply.as_bytes());
        assert_eq!(out, reply);
    }

    #[test]
    fn command_line_carries_generated_tag_and_crlf() {
        let mut raw = ImapRaw::new("CAPABILITY");
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut raw, &mut frag, None);
        let line = str::from_utf8(&bytes).expect("utf8 command");
        let tag = first_word(line);
        assert_eq!(line, format!("{tag} CAPABILITY\r\n"));
    }

    #[test]
    fn tagged_no_is_returned_as_payload_not_error() {
        let mut raw = ImapRaw::new("SELECT INBOX");
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut raw, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command"));

        expect_wants_read(&mut raw, &mut frag);

        let reply = format!("{tag} NO mailbox does not exist\r\n");
        let out = expect_complete_ok(&mut raw, &mut frag, reply.as_bytes());
        assert_eq!(out, reply);
        assert!(out.contains("NO mailbox does not exist"));
    }

    #[test]
    fn response_with_literal_is_captured_verbatim() {
        let mut raw = ImapRaw::new("FETCH 1 BODY[]");
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut raw, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command"));

        expect_wants_read(&mut raw, &mut frag);

        let reply = format!("* 1 FETCH (BODY[] {{3}}\r\nabc)\r\n{tag} OK FETCH completed\r\n");
        let out = expect_complete_ok(&mut raw, &mut frag, reply.as_bytes());
        assert_eq!(out, reply);
        assert!(out.contains("abc"));
    }

    #[test]
    fn eof_before_tagged_returns_error() {
        let mut raw = ImapRaw::new("CAPABILITY");
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

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

    fn first_word(line: &str) -> &str {
        line.split_whitespace()
            .next()
            .expect("first whitespace-separated token")
    }
}
