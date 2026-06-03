//! I/O-free coroutine to perform STARTTLS negotiation (RFC 3501 §6.2.1).
//!
//! The coroutine discards the server greeting, sends a STARTTLS command, and
//! discards the tagged response, then yields
//! [`ImapStartTlsYield::WantsStartTls`] carrying any bytes received past the
//! tagged response so the caller can perform the TLS handshake on the
//! underlying socket. RFC 3501 §6.2.1 forbids the server from sending anything
//! past the tagged response; non-empty bytes here are a classic
//! STARTTLS-injection signal that the caller should refuse.

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

/// Errors that can occur during STARTTLS progression.
#[derive(Clone, Debug, Error)]
pub enum ImapStartTlsError {
    #[error("IMAP STARTTLS failed: reached unexpected EOF on stream")]
    Eof,
}

/// Per-coroutine Yield: socket I/O step requests on one axis, TLS-upgrade
/// hand-off on the other. The driver dispatches on the variant: I/O variants
/// pump the IMAP socket; [`Self::WantsStartTls`] hands the remaining pre-read
/// bytes back to the caller so it can perform the TLS handshake on the
/// underlying socket.
#[derive(Debug)]
pub enum ImapStartTlsYield {
    /// Socket: read more bytes and feed them back on the next resume.
    WantsRead,
    /// Socket: write these bytes; the next resume typically takes `None`.
    WantsWrite(Vec<u8>),
    /// IMAP-layer STARTTLS dance is complete; the driver should now perform the
    /// TLS handshake on the underlying socket. The vec carries any bytes
    /// received past the tagged STARTTLS response (RFC 3501 §6.2.1 forbids any;
    /// non-empty here is a classic STARTTLS-injection signal). After the
    /// upgrade the coroutine has no more work; one extra resume completes with
    /// `Ok(())`.
    WantsStartTls(Vec<u8>),
}

impl From<ImapYield> for ImapStartTlsYield {
    fn from(y: ImapYield) -> Self {
        match y {
            ImapYield::WantsRead => ImapStartTlsYield::WantsRead,
            ImapYield::WantsWrite(bytes) => ImapStartTlsYield::WantsWrite(bytes),
        }
    }
}

/// I/O-free STARTTLS coroutine.
pub struct ImapStartTls {
    tag_bytes: Vec<u8>,
    state: State,
    wants_read: bool,
    wants_write: Option<Vec<u8>>,
    wants_start_tls: Option<Vec<u8>>,
    buf: Vec<u8>,
}

impl ImapStartTls {
    /// Creates a new STARTTLS coroutine.
    pub fn new() -> Self {
        let tag_bytes = TagGenerator::new().generate().as_ref().as_bytes().to_vec();

        Self {
            tag_bytes,
            state: State::DiscardGreeting,
            wants_read: false,
            wants_write: None,
            wants_start_tls: None,
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
    type Yield = ImapStartTlsYield;
    type Return = Result<(), ImapStartTlsError>;

    fn resume(
        &mut self,
        _fragmentizer: &mut Fragmentizer,
        mut arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        loop {
            trace!("starttls: {}", self.state);

            if let Some(bytes) = self.wants_write.take() {
                return ImapCoroutineState::Yielded(ImapStartTlsYield::WantsWrite(bytes));
            }

            if let Some(remaining) = self.wants_start_tls.take() {
                self.state = State::Done;
                return ImapCoroutineState::Yielded(ImapStartTlsYield::WantsStartTls(remaining));
            }

            if mem::take(&mut self.wants_read) {
                return ImapCoroutineState::Yielded(ImapStartTlsYield::WantsRead);
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
                        // SAFETY: tag is always valid.
                        let tag: Tag = self.tag_bytes.as_slice().try_into().unwrap();
                        let starttls = Command {
                            tag,
                            body: CommandBody::StartTLS,
                        };

                        let Some(Fragment::Line { data }) = encoder.encode(&starttls).next() else {
                            // SAFETY: STARTTLS is one simple line.
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
                        self.wants_start_tls = Some(remaining);
                    }
                    None => {
                        self.wants_read = true;
                    }
                },
                State::Done => {
                    return ImapCoroutineState::Complete(Ok(()));
                }
            }
        }
    }
}

enum State {
    /// Discard the greeting line before sending STARTTLS.
    DiscardGreeting,
    /// Push the STARTTLS command onto the write queue.
    WriteStartTls,
    /// Discard the tagged STARTTLS response and capture any trailing
    /// bytes for the WantsStartTls hand-off.
    DiscardStartTls,
    /// Terminal state reached after the WantsStartTls yield; the next
    /// resume completes with `Ok(())`.
    Done,
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DiscardGreeting => f.write_str("discard greeting"),
            Self::WriteStartTls => f.write_str("write starttls"),
            Self::DiscardStartTls => f.write_str("discard starttls response"),
            Self::Done => f.write_str("done"),
        }
    }
}
