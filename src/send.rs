//! Base coroutine that all higher-level IMAP coroutines delegate to.
//!
//! Serialises a command via `imap_codec`, exchanges the bytes with the
//! caller, and feeds responses back through the borrowed
//! `Fragmentizer`.

use core::mem;

use alloc::{boxed::Box, collections::VecDeque, vec::Vec};

use imap_codec::{
    CommandCodec, ResponseCodec,
    encode::{Encoder, Fragment},
    fragmentizer::{DecodeMessageError, FragmentInfo, Fragmentizer},
    imap_types::{
        IntoStatic,
        command::{Command, CommandBody},
        core::{LiteralMode, Tag},
        error::ValidationError,
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
    /// The caller resumed a `WantsTag` without a tag.
    #[error("Missing IMAP command tag")]
    MissingTag,
    /// The caller resumed a `WantsTag` with bytes that are not a valid
    /// IMAP tag.
    #[error("Invalid IMAP command tag")]
    InvalidTag(#[source] ValidationError),
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
    /// The caller resumes with the tag of the command to send.
    WantsTag,
    /// The caller reads from its stream and resumes with the bytes.
    WantsRead,
    /// The caller writes the given bytes to its stream and resumes.
    WantsWrite(Vec<u8>),
    /// The exchange failed.
    Err(ImapSendError),
}

#[derive(Debug)]
enum State {
    Tag,
    Serialize,
    Read,
    Deserialize,
}

/// I/O-free coroutine sending one IMAP command and parsing its response.
pub struct ImapSend<T: Encoder> {
    encoder: T,
    message: Option<T::Message<'static>>,
    untagged_command: Option<UntaggedCommand<T>>,
    tag_requested: bool,
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
            encoder,
            message: Some(message),
            untagged_command: None,
            tag_requested: false,
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
    pub fn receive(message: T::Message<'static>) -> Self
    where
        T: Default,
    {
        Self {
            encoder: T::default(),
            message: Some(message),
            untagged_command: None,
            tag_requested: false,
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

    /// Pass `None` initially or after `WantsWrite`, `Some(tag)` after
    /// `WantsTag`, `Some(bytes)` after `WantsRead`, `Some(&[])` on EOF.
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
                State::Tag => match arg.take() {
                    Some(bytes) => {
                        let tag = match Tag::try_from(bytes) {
                            Ok(tag) => tag.into_static(),
                            Err(err) => return ImapSendResult::Err(ImapSendError::InvalidTag(err)),
                        };

                        // NOTE: the untagged command always exists in the
                        // tag state.
                        let untagged = self.untagged_command.take().unwrap();
                        let message = (untagged.into_message)(Command {
                            tag,
                            body: untagged.body,
                        });

                        self.fragments = self.encoder.encode(&message).collect();
                        self.message = Some(message);
                        self.state = State::Serialize;
                    }
                    None if self.tag_requested => {
                        return ImapSendResult::Err(ImapSendError::MissingTag);
                    }
                    None => {
                        self.tag_requested = true;
                        return ImapSendResult::WantsTag;
                    }
                },
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

impl ImapSend<CommandCodec> {
    /// Builds a send for a command whose tag the caller supplies: the
    /// first resume yields `WantsTag`, and the command is serialised
    /// once resumed with the tag.
    pub fn command(body: CommandBody<'static>) -> Self {
        Self {
            encoder: CommandCodec::new(),
            message: None,
            untagged_command: Some(UntaggedCommand {
                body,
                into_message: |command| command,
            }),
            tag_requested: false,
            codec: ResponseCodec::new(),
            state: State::Tag,
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
}

/// A command body waiting for its tag, with the conversion from the
/// tagged command to the encoder's message type (the identity for
/// [`CommandCodec`]).
struct UntaggedCommand<T: Encoder> {
    body: CommandBody<'static>,
    into_message: fn(Command<'static>) -> T::Message<'static>,
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
            ImapSendResult::WantsTag => ImapCoroutineState::Yielded(ImapYield::WantsTag),
            ImapSendResult::WantsRead => ImapCoroutineState::Yielded(ImapYield::WantsRead),
            ImapSendResult::WantsWrite(bytes) => {
                ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes))
            }
            ImapSendResult::Ok(output) => ImapCoroutineState::Complete(Ok(*output)),
            ImapSendResult::Err(err) => ImapCoroutineState::Complete(Err(err)),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::str;

    use crate::send::*;

    #[test]
    fn command_tag_answered_writes_tagged_command() {
        let mut send = ImapSend::command(CommandBody::Noop);
        let mut frag = Fragmentizer::new(1024);

        assert!(matches!(
            send.resume(&mut frag, None),
            ImapSendResult::WantsTag
        ));

        let ImapSendResult::WantsWrite(bytes) = send.resume(&mut frag, Some(b"A1")) else {
            panic!("expected WantsWrite");
        };
        assert_eq!("A1 NOOP\r\n", str::from_utf8(&bytes).expect("utf8 command"));
    }

    #[test]
    fn command_tag_missing_returns_missing_tag_error() {
        let mut send = ImapSend::command(CommandBody::Noop);
        let mut frag = Fragmentizer::new(1024);

        assert!(matches!(
            send.resume(&mut frag, None),
            ImapSendResult::WantsTag
        ));
        assert!(matches!(
            send.resume(&mut frag, None),
            ImapSendResult::Err(ImapSendError::MissingTag)
        ));
    }

    #[test]
    fn command_tag_invalid_returns_invalid_tag_error() {
        let mut send = ImapSend::command(CommandBody::Noop);
        let mut frag = Fragmentizer::new(1024);

        assert!(matches!(
            send.resume(&mut frag, None),
            ImapSendResult::WantsTag
        ));
        assert!(matches!(
            send.resume(&mut frag, Some(b"A+1")),
            ImapSendResult::Err(ImapSendError::InvalidTag(_))
        ));
    }
}
