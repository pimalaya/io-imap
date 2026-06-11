//! Base coroutine that all higher-level IMAP coroutines delegate to:
//! serialises a command via `imap_codec`, drives read/write, and feeds
//! responses back through the borrowed `Fragmentizer`.

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
use log::{trace, warn};
use thiserror::Error;

use crate::coroutine::{ImapCoroutine, ImapCoroutineState, ImapYield};

/// Failure causes raised by [`SendImapCommand`].
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

/// Step output emitted by [`SendImapCommand::resume`].
pub enum SendImapCommandResult<T: Encoder> {
    Ok {
        message: T::Message<'static>,
        data: Vec<Data<'static>>,
        untagged: Vec<StatusBody<'static>>,
        tagged: Option<Tagged<'static>>,
        bye: Option<Bye<'static>>,
        continuation_request: Option<CommandContinuationRequest<'static>>,
    },
    WantsRead,
    WantsWrite(Vec<u8>),
    Err(SendImapCommandError),
}

#[derive(Debug)]
enum State {
    Serialize,
    Read,
    Deserialize,
}

/// I/O-free coroutine sending one IMAP command and parsing its response.
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

    /// Pass `None` initially or after `WantsWrite`, `Some(bytes)`
    /// after `WantsRead`, `Some(&[])` on EOF.
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

                    if !buf.is_empty() {
                        self.wants_write = Some(buf);
                    }
                    self.state = State::Read;
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
                                let err = match decode_err {
                                    DecodeMessageError::DecodingFailure(_)
                                    | DecodeMessageError::DecodingRemainder { .. } => {
                                        // Don't fail the whole command when an untagged response cannot be decoded: skip it with a warning (pimalaya/himalaya#641).
                                        if bytes.starts_with(b"* ") {
                                            warn!(
                                                "skipping undecodable untagged response: {}",
                                                escape_byte_string(bytes)
                                            );
                                            continue;
                                        }
                                        SendImapCommandError::DecodingFailure(Secret::new(
                                            bytes.into(),
                                        ))
                                    }
                                    DecodeMessageError::MessageTooLong { .. } => {
                                        SendImapCommandError::MessageTooLong(Secret::new(
                                            bytes.into(),
                                        ))
                                    }
                                    DecodeMessageError::MessagePoisoned { .. } => {
                                        SendImapCommandError::MessageIsPoisoned(Secret::new(
                                            bytes.into(),
                                        ))
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

/// Trait-surface successful output: mirror of [`SendImapCommandResult::Ok`].
#[derive(Debug)]
pub struct SendImapCommandOk<T: Encoder> {
    pub message: T::Message<'static>,
    pub data: Vec<Data<'static>>,
    pub untagged: Vec<StatusBody<'static>>,
    pub tagged: Option<Tagged<'static>>,
    pub bye: Option<Bye<'static>>,
    pub continuation_request: Option<CommandContinuationRequest<'static>>,
}

impl<T: Encoder> ImapCoroutine for SendImapCommand<T> {
    type Yield = ImapYield;
    type Return = Result<SendImapCommandOk<T>, SendImapCommandError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        // NOTE: qualified path avoids recursing into this trait impl.
        match SendImapCommand::<T>::resume(self, fragmentizer, arg) {
            SendImapCommandResult::WantsRead => ImapCoroutineState::Yielded(ImapYield::WantsRead),
            SendImapCommandResult::WantsWrite(bytes) => {
                ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes))
            }
            SendImapCommandResult::Ok {
                message,
                data,
                untagged,
                tagged,
                bye,
                continuation_request,
            } => ImapCoroutineState::Complete(Ok(SendImapCommandOk {
                message,
                data,
                untagged,
                tagged,
                bye,
                continuation_request,
            })),
            SendImapCommandResult::Err(err) => ImapCoroutineState::Complete(Err(err)),
        }
    }
}
