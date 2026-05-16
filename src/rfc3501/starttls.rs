//! I/O-free coroutine to perform STARTTLS negotiation.
//!
//! The coroutine discards the server greeting, sends a STARTTLS
//! command, and discards the tagged response; at which point it
//! yields [`ImapStartTlsResult::WantsStartTls`] for the caller to
//! perform the TLS handshake on the underlying socket. Any bytes
//! received after the tagged response (which RFC 3501 §6.2.1
//! forbids) are returned in `remaining` so the caller can decide
//! how to handle them.

use alloc::vec::Vec;
use core::mem;

use imap_codec::{
    CommandCodec,
    encode::{Encoder, Fragment},
    imap_types::{
        command::{Command, CommandBody},
        core::Tag,
        utils::escape_byte_string,
    },
};
use log::trace;
use thiserror::Error;

use crate::context::ImapContext;

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum ImapStartTlsError {
    #[error("Reached unexpected EOF on IMAP stream")]
    Eof,
}

/// Output emitted when the coroutine terminates its progression.
pub enum ImapStartTlsResult {
    /// The STARTTLS handshake on the IMAP layer is complete and the
    /// caller should now perform the TLS handshake on the socket.
    WantsStartTls {
        context: ImapContext,
        /// Bytes received after the tagged response (should be empty
        /// per RFC 3501 §6.2.1).
        remaining: Vec<u8>,
    },
    WantsRead,
    WantsWrite(Vec<u8>),
    Err {
        context: ImapContext,
        err: ImapStartTlsError,
    },
}

enum State {
    /// Greeting needs to be discarded.
    DiscardGreeting,
    /// The STARTTLS command needs to be written.
    WriteStartTls,
    /// The STARTTLS response needs to be discarded.
    DiscardStartTls,
}

/// I/O-free coroutine to perform STARTTLS negotiation.
pub struct ImapStartTls {
    context: Option<ImapContext>,
    tag_bytes: Vec<u8>,
    state: State,
    wants_read: bool,
    wants_write: Option<Vec<u8>>,
    buf: Vec<u8>,
}

impl ImapStartTls {
    /// Creates a new coroutine.
    pub fn new(mut context: ImapContext) -> Self {
        let tag = context.generate_tag();
        let tag_bytes = tag.as_ref().as_bytes().to_vec();

        Self {
            context: Some(context),
            tag_bytes,
            state: State::DiscardGreeting,
            wants_read: false,
            wants_write: None,
            buf: Vec::new(),
        }
    }

    /// Advances the coroutine.
    pub fn resume(&mut self, mut arg: Option<&[u8]>) -> ImapStartTlsResult {
        loop {
            if let Some(bytes) = self.wants_write.take() {
                return ImapStartTlsResult::WantsWrite(bytes);
            }

            if mem::take(&mut self.wants_read) {
                return ImapStartTlsResult::WantsRead;
            }

            match self.state {
                State::DiscardGreeting => match arg.take() {
                    Some(&[]) => {
                        let context = self.context.take().unwrap();
                        return ImapStartTlsResult::Err {
                            context,
                            err: ImapStartTlsError::Eof,
                        };
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
                        // SAFETY: tag is always valid
                        let tag: Tag = self.tag_bytes.as_slice().try_into().unwrap();
                        let starttls = Command::new(tag, CommandBody::StartTLS).unwrap();

                        let Some(Fragment::Line { data }) = encoder.encode(&starttls).next() else {
                            // SAFETY: STARTTLS is one simple line
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
                        let context = self.context.take().unwrap();
                        return ImapStartTlsResult::Err {
                            context,
                            err: ImapStartTlsError::Eof,
                        };
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
                        let context = self.context.take().unwrap();

                        return ImapStartTlsResult::WantsStartTls { context, remaining };
                    }
                    None => {
                        self.wants_read = true;
                    }
                },
            }
        }
    }
}
