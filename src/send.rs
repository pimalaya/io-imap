//! Base coroutine that all higher-level IMAP coroutines delegate to.
//!
//! Serialises a command via `imap_codec`, exchanges the bytes with the
//! caller, and feeds responses back through the borrowed
//! `Fragmentizer`.

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
use log::{debug, trace};
use thiserror::Error;

use crate::coroutine::{ImapCoroutine, ImapCoroutineState, ImapYield};

/// Failure causes raised by [`ImapSend`].
#[derive(Clone, Debug, Error)]
pub enum ImapSendError {
    /// The stream reached EOF before the tagged response arrived.
    #[error("Reached unexpected EOF on IMAP stream")]
    Eof,
    /// A response line could not be decoded; carries the raw bytes.
    #[error("Decode IMAP response error")]
    DecodingFailure(Secret<Box<[u8]>>),
    /// The `Fragmentizer` poisoned the message after a framing error;
    /// carries the raw bytes.
    #[error("Parse IMAP response error: message is poisoned")]
    MessageIsPoisoned(Secret<Box<[u8]>>),
    /// The response message exceeded the `Fragmentizer` size limit;
    /// carries the raw bytes.
    #[error("Parse IMAP response error: message is too long")]
    MessageTooLong(Secret<Box<[u8]>>),
}

/// Step output emitted by [`ImapSend::resume`].
pub enum ImapSendResult<T: Encoder> {
    /// The exchange completed; carries the boxed output (boxed to keep
    /// the enum small next to the I/O variants).
    Ok(Box<ImapSendOutput<T>>),
    /// The caller reads from its stream and resumes with the bytes.
    WantsRead,
    /// The caller writes the given bytes to its stream and resumes.
    WantsWrite(Vec<u8>),
    /// The exchange failed.
    Err(ImapSendError),
}

#[derive(Debug)]
enum State {
    Serialize,
    Read,
    Deserialize,
}

/// I/O-free coroutine sending one IMAP command and parsing its response.
pub struct ImapSend<T: Encoder> {
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

impl<T: Encoder> ImapSend<T> {
    /// Builds a send serialising `message` through `encoder` and
    /// parsing its response.
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

    /// Receive-only: skips serialisation and parses the response of a
    /// request whose bytes were written out of band.
    ///
    /// Used by the streamed APPEND literal; `message` is echoed back
    /// unchanged in the Ok output.
    pub fn receive(message: T::Message<'static>) -> Self {
        Self {
            message: Some(message),
            codec: ResponseCodec::new(),
            state: State::Read,
            wants_read: false,
            wants_write: None,
            fragments: VecDeque::new(),
            data: Vec::new(),
            untagged: Vec::new(),
            tagged: None,
            bye: None,
            cr: None,
            limbo_literal: None,
            done: false,
        }
    }

    /// Pass `None` initially or after `WantsWrite`, `Some(bytes)`
    /// after `WantsRead`, `Some(&[])` on EOF.
    pub fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        mut arg: Option<&[u8]>,
    ) -> ImapSendResult<T> {
        loop {
            if let Some(bytes) = self.wants_write.take() {
                return ImapSendResult::WantsWrite(bytes);
            }

            if mem::take(&mut self.wants_read) {
                return ImapSendResult::WantsRead;
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

                    if !buf.is_empty() {
                        self.wants_write = Some(buf);
                    }
                    self.state = State::Read;
                }
                State::Read => match arg.take() {
                    Some(&[]) => {
                        return ImapSendResult::Err(ImapSendError::Eof);
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
                                let err = match decode_err {
                                    DecodeMessageError::DecodingFailure(_)
                                    | DecodeMessageError::DecodingRemainder { .. } => {
                                        // NOTE: do not fail the whole
                                        // command when an untagged
                                        // response cannot be decoded:
                                        // skip it with a warning
                                        // (pimalaya/himalaya#641).
                                        if bytes.starts_with(b"* ") {
                                            debug!("skipping undecodable untagged response");
                                            trace!("{}", escape_byte_string(bytes));
                                            continue;
                                        }

                                        let err = Secret::new(bytes.into());
                                        ImapSendError::DecodingFailure(err)
                                    }
                                    DecodeMessageError::MessageTooLong { .. } => {
                                        let err = Secret::new(bytes.into());
                                        ImapSendError::MessageTooLong(err)
                                    }
                                    DecodeMessageError::MessagePoisoned { .. } => {
                                        let err = Secret::new(bytes.into());
                                        ImapSendError::MessageIsPoisoned(err)
                                    }
                                };

                                return ImapSendResult::Err(err);
                            }
                        }
                    }
                    Some(info @ FragmentInfo::Literal { .. }) => {
                        let bytes = fragmentizer.fragment_bytes(info);
                        trace!("read literal fragment ({} bytes)", bytes.len());
                    }
                    None if self.done => {
                        // NOTE: message always exists during a resume cycle.
                        return ImapSendResult::Ok(Box::new(ImapSendOutput {
                            message: self.message.take().unwrap(),
                            data: mem::take(&mut self.data),
                            untagged: mem::take(&mut self.untagged),
                            tagged: self.tagged.take(),
                            bye: self.bye.take(),
                            continuation_request: self.cr.take(),
                        }));
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

/// Successful output of one command exchange: the echoed message plus
/// everything the server answered before the tagged response.
#[derive(Debug)]
pub struct ImapSendOutput<T: Encoder> {
    /// The sent message, echoed back to the caller.
    pub message: T::Message<'static>,
    /// The untagged data responses collected during the exchange.
    pub data: Vec<Data<'static>>,
    /// The untagged status responses collected during the exchange.
    pub untagged: Vec<StatusBody<'static>>,
    /// The tagged response terminating the exchange, when one arrived.
    pub tagged: Option<Tagged<'static>>,
    /// The BYE response, when the server closed the session instead.
    pub bye: Option<Bye<'static>>,
    /// The continuation request that paused the exchange, when the
    /// server asked for more data.
    pub continuation_request: Option<CommandContinuationRequest<'static>>,
}

impl<T: Encoder> ImapCoroutine for ImapSend<T> {
    type Yield = ImapYield;
    type Return = Result<ImapSendOutput<T>, ImapSendError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        // NOTE: qualified path avoids recursing into this trait impl.
        match ImapSend::<T>::resume(self, fragmentizer, arg) {
            ImapSendResult::WantsRead => ImapCoroutineState::Yielded(ImapYield::WantsRead),
            ImapSendResult::WantsWrite(bytes) => {
                ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes))
            }
            ImapSendResult::Ok(output) => ImapCoroutineState::Complete(Ok(*output)),
            ImapSendResult::Err(err) => ImapCoroutineState::Complete(Err(err)),
        }
    }
}
