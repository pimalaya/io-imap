//! I/O-free coroutine to send an IMAP command and receive a response.
//!
//! This is the base coroutine that all higher-level IMAP coroutines delegate
//! to. It serialises the command via `imap_codec`, drives the read/write cycle
//! via [`SendImapCommandResult::WantsRead`] /
//! [`SendImapCommandResult::WantsWrite`], and feeds the response bytes back
//! through a borrowed [`Fragmentizer`].
//!
//! Callers drive the coroutine in a loop:
//!
//! ```rust,ignore
//! let mut fragmentizer = Fragmentizer::new(50 * 1024 * 1024);
//! let mut send = SendImapCommand::new(codec, message);
//! let mut arg: Option<&[u8]> = None;
//!
//! loop {
//!     match send.resume(&mut fragmentizer, arg.take()) {
//!         SendImapCommandResult::Ok { .. } => break,
//!         SendImapCommandResult::Err(err) => panic!("{err}"),
//!         SendImapCommandResult::WantsRead => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         SendImapCommandResult::WantsWrite(bytes) => stream.write_all(&bytes).unwrap(),
//!     }
//! }
//! ```
//!
//! [`Fragmentizer`]: imap_codec::fragmentizer::Fragmentizer

use core::mem;

use alloc::{boxed::Box, collections::VecDeque, vec::Vec};

use imap_codec::{
    ResponseCodec,
    encode::{Encoder, Fragment},
    fragmentizer::{DecodeMessageError, FragmentInfo, Fragmentizer},
    imap_types::{
        IntoStatic,
        core::LiteralMode,
        response::{Bye, CommandContinuationRequest, Data, Response, Status, StatusBody, Tagged},
        secret::Secret,
        utils::escape_byte_string,
    },
};
use log::trace;
use thiserror::Error;

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum SendImapCommandError {
    #[error("Reached unexpected EOF on IMAP stream")]
    Eof,
    #[error("Decode IMAP response error")]
    DecodingFailure(Secret<Box<[u8]>>),
    #[error("Parse IMAP response error: message is poisoned")]
    MessageIsPoisoned(Secret<Box<[u8]>>),
    #[error("Parse IMAP response error: message is too long")]
    MessageTooLong(Secret<Box<[u8]>>),
}

/// Output emitted when the coroutine terminates its progression.
pub enum SendImapCommandResult<T: Encoder> {
    /// The coroutine has successfully terminated its execution.
    Ok {
        message: T::Message<'static>,
        data: Vec<Data<'static>>,
        untagged: Vec<StatusBody<'static>>,
        tagged: Option<Tagged<'static>>,
        bye: Option<Bye<'static>>,
        continuation_request: Option<CommandContinuationRequest<'static>>,
    },
    /// The coroutine needs more bytes to be read from the IMAP stream.
    WantsRead,
    /// The coroutine wants the given bytes to be written to the IMAP stream.
    WantsWrite(Vec<u8>),
    /// The coroutine encountered an error.
    Err(SendImapCommandError),
}

#[derive(Debug)]
enum State {
    /// Pull line/literal fragments from the encoder into a write buffer.
    Serialize,
    /// Drain `arg` into the fragmentizer (or yield [`WantsRead`] when empty).
    ///
    /// [`WantsRead`]: SendImapCommandResult::WantsRead
    Read,
    /// Decode the bytes accumulated in the fragmentizer.
    Deserialize,
}

/// I/O-free coroutine to send an IMAP command and receive a response.
pub struct SendImapCommand<T: Encoder> {
    message: Option<T::Message<'static>>,
    state: State,
    wants_read: bool,
    wants_write: Option<Vec<u8>>,
    fragments: VecDeque<Fragment>,
    codec: ResponseCodec,
    data: Vec<Data<'static>>,
    untagged: Vec<StatusBody<'static>>,
    tagged: Option<Tagged<'static>>,
    bye: Option<Bye<'static>>,
    cr: Option<CommandContinuationRequest<'static>>,
    limbo_literal: Option<Vec<u8>>,
    done: bool,
}

impl<T: Encoder> SendImapCommand<T> {
    /// Creates a new coroutine for the given message.
    pub fn new(encoder: T, message: T::Message<'static>) -> Self {
        let fragments = encoder.encode(&message).collect();

        Self {
            message: Some(message),
            codec: ResponseCodec::new(),
            state: State::Serialize,
            wants_read: false,
            wants_write: None,
            fragments,
            data: Vec::new(),
            untagged: Vec::new(),
            tagged: None,
            bye: None,
            cr: None,
            limbo_literal: None,
            done: false,
        }
    }

    /// Advances the coroutine.
    ///
    /// Pass [`None`] when there is no data to provide (initial call,
    /// after a write). Pass `Some(data)` with bytes read from the
    /// stream after a [`SendImapCommandResult::WantsRead`]. Pass
    /// `Some(&[])` to signal EOF.
    pub fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        mut arg: Option<&[u8]>,
    ) -> SendImapCommandResult<T> {
        loop {
            if let Some(bytes) = self.wants_write.take() {
                return SendImapCommandResult::WantsWrite(bytes);
            }

            if mem::take(&mut self.wants_read) {
                return SendImapCommandResult::WantsRead;
            }

            match self.state {
                State::Serialize => {
                    let mut buf = Vec::new();

                    if let Some(bytes) = self.limbo_literal.take() {
                        buf.extend(bytes);
                    }

                    while let Some(fragment) = self.fragments.pop_front() {
                        match fragment {
                            Fragment::Line { data } => {
                                buf.extend(data);
                            }
                            Fragment::Literal { data, mode } => match mode {
                                LiteralMode::NonSync => {
                                    buf.extend(data);
                                }
                                LiteralMode::Sync => {
                                    self.limbo_literal.replace(data);
                                    break;
                                }
                            },
                        }
                    }

                    if buf.is_empty() {
                        // Nothing pending to send: expect a server message
                        // (e.g. tagged response after the previous write,
                        // or further data once the read state is entered).
                        self.state = State::Read;
                    } else {
                        trace!("command to write: {}", escape_byte_string(&buf));
                        self.wants_write = Some(buf);
                        self.state = State::Read;
                    }
                }
                State::Read => match arg.take() {
                    Some(&[]) => {
                        return SendImapCommandResult::Err(SendImapCommandError::Eof);
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
                    Some(info @ FragmentInfo::Line { .. }) => {
                        let bytes = fragmentizer.fragment_bytes(info);
                        trace!("read line fragment: {}", escape_byte_string(bytes));

                        if !fragmentizer.is_message_complete() {
                            continue;
                        }

                        match fragmentizer.decode_message(&self.codec) {
                            Ok(Response::Data(data)) => {
                                self.data.push(data.into_static());
                            }
                            Ok(Response::Status(Status::Untagged(status))) => {
                                self.untagged.push(status.into_static());
                            }
                            Ok(Response::Status(Status::Tagged(tagged))) => {
                                self.tagged.replace(tagged.into_static());
                                self.done = true;
                            }
                            Ok(Response::Status(Status::Bye(bye))) => {
                                self.bye.replace(bye.into_static());
                                self.done = true;
                            }
                            Ok(Response::CommandContinuationRequest(cr)) => {
                                self.cr.replace(cr.into_static());
                                self.done = self.limbo_literal.is_none();
                            }
                            Err(decode_err) => {
                                let bytes = fragmentizer.message_bytes();
                                let bytes = Secret::new(bytes.into());
                                let err = match decode_err {
                                    DecodeMessageError::DecodingFailure(_)
                                    | DecodeMessageError::DecodingRemainder { .. } => {
                                        SendImapCommandError::DecodingFailure(bytes)
                                    }
                                    DecodeMessageError::MessageTooLong { .. } => {
                                        SendImapCommandError::MessageTooLong(bytes)
                                    }
                                    DecodeMessageError::MessagePoisoned { .. } => {
                                        SendImapCommandError::MessageIsPoisoned(bytes)
                                    }
                                };
                                return SendImapCommandResult::Err(err);
                            }
                        }
                    }
                    Some(info @ FragmentInfo::Literal { .. }) => {
                        let bytes = fragmentizer.fragment_bytes(info);
                        trace!("read literal fragment ({} bytes)", bytes.len());
                    }
                    None if self.done => {
                        // SAFETY: message always exists during a resume cycle
                        return SendImapCommandResult::Ok {
                            message: self.message.take().unwrap(),
                            data: mem::take(&mut self.data),
                            untagged: mem::take(&mut self.untagged),
                            tagged: self.tagged.take(),
                            bye: self.bye.take(),
                            continuation_request: self.cr.take(),
                        };
                    }
                    None if self.limbo_literal.is_some() => {
                        self.state = State::Serialize;
                    }
                    None => {
                        self.state = State::Read;
                    }
                },
            }
        }
    }
}
