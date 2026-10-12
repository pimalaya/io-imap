//! IMAP STARTTLS coroutine; returns any bytes received past the tagged
//! response.
//!
//! RFC 3501 §6.2.1 forbids trailing bytes, so a non-empty return value is
//! a STARTTLS-injection signal: refuse the upgrade.
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
//!     rfc3501::starttls::ImapStartTls,
//! };
//!
//! // Ready stream needed (TCP-connected, plain IMAP)
//! let mut stream = TcpStream::connect("localhost:143").unwrap();
//!
//! let mut fragmentizer = Fragmentizer::new(50 * 1024 * 1024);
//! let mut buf = [0u8; 4096];
//!
//! let mut coroutine = ImapStartTls::new();
//! let mut arg = None;
//!
//! let leftover = loop {
//!     match coroutine.resume(&mut fragmentizer, arg.take()) {
//!         ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         ImapCoroutineState::Complete(Ok(leftover)) => break leftover,
//!         ImapCoroutineState::Complete(Err(err)) => panic!("{err}"),
//!     }
//! };
//!
//! assert!(leftover.is_empty(), "STARTTLS-injection: refuse the upgrade");
//! // Now upgrade `stream` to TLS before sending further IMAP commands.
//! ```

use core::{fmt, mem};

use alloc::vec::Vec;

use imap_codec::{
    CommandCodec,
    encode::{Encoder, Fragment},
    fragmentizer::Fragmentizer,
    imap_types::{
        command::{Command, CommandBody},
        core::{Tag, TagGenerator},
        utils::escape_byte_string,
    },
};
use log::trace;
use thiserror::Error;

use crate::coroutine::*;

/// Failure causes during the IMAP STARTTLS handshake.
#[derive(Clone, Debug, Error)]
pub enum ImapStartTlsError {
    /// The stream reached EOF during the STARTTLS exchange.
    #[error("IMAP STARTTLS failed: reached unexpected EOF on stream")]
    Eof,
    /// A response line ran past the given number of octets.
    #[error("IMAP STARTTLS failed: response line longer than {0} octets")]
    LineTooLong(usize),
}

/// Longest response line accepted before the upgrade, in octets.
const MAX_LINE_LEN: usize = 64 * 1024;

/// I/O-free IMAP STARTTLS coroutine.
pub struct ImapStartTls {
    tag_bytes: Vec<u8>,
    state: State,
    wants_read: bool,
    wants_write: Option<Vec<u8>>,
    buf: Vec<u8>,
    scanned: usize,
}

impl ImapStartTls {
    /// Builds a STARTTLS coroutine discarding the plain-text greeting,
    /// requesting the upgrade and returning any leftover bytes.
    pub fn new() -> Self {
        let tag_bytes = TagGenerator::new().generate().as_ref().as_bytes().to_vec();

        Self {
            tag_bytes,
            state: State::DiscardGreeting,
            wants_read: false,
            wants_write: None,
            buf: Vec::new(),
            scanned: 0,
        }
    }

    /// Takes the next complete line off the buffer, `None` when more
    /// must be read.
    ///
    /// Only the octets not yet scanned are searched, and a line is capped:
    /// this runs in plaintext, so anyone on the path controls the input.
    fn next_line(&mut self) -> Result<Option<Vec<u8>>, ImapStartTlsError> {
        let unscanned = &self.buf[self.scanned..];

        let Some(pos) = unscanned.iter().position(|&b| b == b'\n') else {
            self.scanned = self.buf.len();

            if self.scanned > MAX_LINE_LEN {
                return Err(ImapStartTlsError::LineTooLong(MAX_LINE_LEN));
            }

            return Ok(None);
        };

        let nl = self.scanned + pos;
        self.scanned = 0;

        if nl >= MAX_LINE_LEN {
            return Err(ImapStartTlsError::LineTooLong(MAX_LINE_LEN));
        }

        Ok(Some(self.buf.drain(..=nl).collect()))
    }
}

impl Default for ImapStartTls {
    fn default() -> Self {
        Self::new()
    }
}

impl ImapCoroutine for ImapStartTls {
    type Yield = ImapYield;
    type Return = Result<Vec<u8>, ImapStartTlsError>;

    fn resume(
        &mut self,
        _fragmentizer: &mut Fragmentizer,
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
                State::DiscardGreeting => match arg.take() {
                    Some(&[]) => {
                        return ImapCoroutineState::Complete(Err(ImapStartTlsError::Eof));
                    }
                    Some(data) => {
                        self.buf.extend_from_slice(data);

                        let line = match self.next_line() {
                            Ok(Some(line)) => line,
                            Ok(None) => {
                                self.wants_read = true;
                                continue;
                            }
                            Err(err) => return ImapCoroutineState::Complete(Err(err)),
                        };

                        trace!("discard greeting line: {}", escape_byte_string(&line));

                        let encoder = CommandCodec::new();
                        // NOTE: the tag is always valid.
                        let tag: Tag = self.tag_bytes.as_slice().try_into().unwrap();
                        let starttls = Command {
                            tag,
                            body: CommandBody::StartTLS,
                        };

                        let Some(Fragment::Line { data }) = encoder.encode(&starttls).next() else {
                            // NOTE: STARTTLS is one simple line.
                            unreachable!();
                        };

                        trace!("write starttls command: {}", escape_byte_string(&data));
                        self.wants_write = Some(data);
                        self.state = State::WriteStartTls;
                    }
                    None => {
                        self.wants_read = true;
                    }
                },
                State::WriteStartTls => {
                    self.state = State::DiscardStartTls;
                }
                State::DiscardStartTls => match arg.take() {
                    Some(&[]) => {
                        return ImapCoroutineState::Complete(Err(ImapStartTlsError::Eof));
                    }
                    Some(data) => {
                        self.buf.extend_from_slice(data);

                        // NOTE: lines before the tagged one are untagged
                        // responses to discard; the tag is only matched at
                        // the start of a line.
                        loop {
                            let line = match self.next_line() {
                                Ok(Some(line)) => line,
                                Ok(None) => {
                                    self.wants_read = true;
                                    break;
                                }
                                Err(err) => return ImapCoroutineState::Complete(Err(err)),
                            };

                            trace!(
                                "discard STARTTLS response line: {}",
                                escape_byte_string(&line)
                            );

                            let tagged = line.starts_with(&self.tag_bytes)
                                && line.get(self.tag_bytes.len()) == Some(&b' ');

                            if tagged {
                                let remaining = mem::take(&mut self.buf);
                                return ImapCoroutineState::Complete(Ok(remaining));
                            }
                        }
                    }
                    None => {
                        self.wants_read = true;
                    }
                },
            }
        }
    }
}

enum State {
    DiscardGreeting,
    WriteStartTls,
    DiscardStartTls,
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DiscardGreeting => f.write_str("discard greeting"),
            Self::WriteStartTls => f.write_str("write starttls"),
            Self::DiscardStartTls => f.write_str("discard starttls response"),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::{format, string::String, vec::Vec};

    use crate::rfc3501::starttls::*;

    #[test]
    fn tagged_response_completes_without_leftover() {
        let mut starttls = ImapStartTls::new();
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);
        let tag = write_command(&mut starttls, &mut frag);

        let reply = format!("* CAPABILITY IMAP4rev1\r\n{tag} OK begin TLS\r\n");
        let leftover = expect_complete(&mut starttls, &mut frag, reply.as_bytes()).unwrap();
        assert!(leftover.is_empty());
    }

    #[test]
    fn injected_bytes_are_returned() {
        let mut starttls = ImapStartTls::new();
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);
        let tag = write_command(&mut starttls, &mut frag);

        let reply = format!("{tag} OK begin TLS\r\n* injected\r\n");
        let leftover = expect_complete(&mut starttls, &mut frag, reply.as_bytes()).unwrap();
        assert_eq!(leftover, b"* injected\r\n");
    }

    #[test]
    fn tag_inside_a_line_is_not_the_tagged_response() {
        let mut starttls = ImapStartTls::new();
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);
        let tag = write_command(&mut starttls, &mut frag);

        let reply = format!("* OK {tag} OK fake\r\n");
        match starttls.resume(&mut frag, Some(reply.as_bytes())) {
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    #[test]
    fn endless_greeting_fails_past_the_cap() {
        let mut starttls = ImapStartTls::new();
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);
        let chunk = [b'x'; 1024];

        expect_wants_read(&mut starttls, &mut frag, None);

        for _ in 0..MAX_LINE_LEN / chunk.len() {
            expect_wants_read(&mut starttls, &mut frag, Some(&chunk));
        }

        let err = expect_complete(&mut starttls, &mut frag, &chunk).unwrap_err();
        assert!(matches!(err, ImapStartTlsError::LineTooLong(MAX_LINE_LEN)));
    }

    #[test]
    fn eof_returns_eof_error() {
        let mut starttls = ImapStartTls::new();
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        expect_wants_read(&mut starttls, &mut frag, None);

        let err = expect_complete(&mut starttls, &mut frag, b"").unwrap_err();
        assert!(matches!(err, ImapStartTlsError::Eof));
    }

    /// Feeds the greeting, then returns the tag of the written command,
    /// leaving the coroutine waiting for the STARTTLS response.
    fn write_command(cor: &mut ImapStartTls, frag: &mut Fragmentizer) -> String {
        expect_wants_read(cor, frag, None);

        let bytes = match cor.resume(frag, Some(b"* OK ready\r\n")) {
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        };

        expect_wants_read(cor, frag, None);

        let command = String::from_utf8(bytes).unwrap();
        let words: Vec<&str> = command.split_whitespace().collect();
        assert_eq!(words[1], "STARTTLS");
        String::from(words[0])
    }

    fn expect_wants_read(cor: &mut ImapStartTls, frag: &mut Fragmentizer, arg: Option<&[u8]>) {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete(
        cor: &mut ImapStartTls,
        frag: &mut Fragmentizer,
        arg: &[u8],
    ) -> Result<Vec<u8>, ImapStartTlsError> {
        match cor.resume(frag, Some(arg)) {
            ImapCoroutineState::Complete(result) => result,
            state => panic!("expected Complete, got {state:?}"),
        }
    }
}
