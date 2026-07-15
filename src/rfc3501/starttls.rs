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
}

/// I/O-free IMAP STARTTLS coroutine.
pub struct ImapStartTls {
    tag_bytes: Vec<u8>,
    state: State,
    wants_read: bool,
    wants_write: Option<Vec<u8>>,
    buf: Vec<u8>,
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
        }
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

                        let Some(pos) = self.buf.iter().position(|&b| b == b'\n') else {
                            self.wants_read = true;
                            continue;
                        };

                        let line = self.buf.drain(..=pos).collect::<Vec<_>>();
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

                        let mut tag_with_space = Vec::with_capacity(self.tag_bytes.len() + 1);
                        tag_with_space.extend(&self.tag_bytes);
                        tag_with_space.push(b' ');

                        let Some(tag_pos) = self
                            .buf
                            .windows(tag_with_space.len())
                            .position(|w| w == tag_with_space.as_slice())
                        else {
                            self.wants_read = true;
                            continue;
                        };

                        let Some(rel) = self.buf[tag_pos..].iter().position(|&b| b == b'\n') else {
                            self.wants_read = true;
                            continue;
                        };

                        let end = tag_pos + rel + 1;
                        let line = &self.buf[tag_pos..end];
                        trace!(
                            "discard STARTTLS response line: {}",
                            escape_byte_string(line)
                        );

                        let remaining = self.buf.split_off(end);
                        return ImapCoroutineState::Complete(Ok(remaining));
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
