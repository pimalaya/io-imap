//! Base coroutine that all higher-level IMAP coroutines delegate to.
//!
//! Serialises a command via `imap_codec`, exchanges the bytes with the
//! caller, and feeds responses back through the borrowed
//! `Fragmentizer`.

use core::{fmt, mem};

use alloc::{
    boxed::Box,
    collections::VecDeque,
    string::{String, ToString},
    vec::Vec,
};

use imap_codec::{
    CommandCodec, ResponseCodec,
    encode::{Encoder, Fragment},
    fragmentizer::{DecodeMessageError, FragmentInfo, Fragmentizer},
    imap_types::{
        IntoStatic,
        command::{Command, CommandBody},
        core::{LiteralMode, Tag},
        error::ValidationError,
        response::{
            Bye, Code, CommandContinuationRequest, Data, Response, Status, StatusBody, StatusKind,
            Tagged,
        },
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
    /// The untagged responses collected before the completion exceeded
    /// the given budget.
    #[error("Read IMAP response error: over {} responses or {} octets", .0.responses, .0.octets)]
    ResponseTooLong(ImapSendBudget),
}

/// A NO or BAD completion: its kind, its response code and its text.
///
/// Shared by the command errors, so a caller reads the response code
/// instead of parsing the text. Displays as the text alone.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc3501#section-7.1>
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImapStatusError {
    /// Whether the server answered NO or BAD.
    pub kind: StatusKind,
    /// The response code, such as `AUTHENTICATIONFAILED` or `TRYCREATE`.
    pub code: Option<Code<'static>>,
    /// The human-readable text.
    pub text: String,
}

impl From<StatusBody<'static>> for ImapStatusError {
    fn from(body: StatusBody<'static>) -> Self {
        Self {
            kind: body.kind,
            code: body.code,
            text: body.text.to_string(),
        }
    }
}

impl fmt::Display for ImapStatusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

/// Bounds on the untagged responses one exchange collects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImapSendBudget {
    /// Largest number of responses collected.
    pub responses: usize,
    /// Largest number of octets these responses add up to on the wire.
    pub octets: usize,
}

impl ImapSendBudget {
    /// Budget of the commands sent before authentication, which are
    /// answered in a handful of lines.
    pub const PRE_AUTH: Self = Self {
        responses: 1024,
        octets: 1024 * 1024,
    };
}

impl Default for ImapSendBudget {
    fn default() -> Self {
        Self {
            responses: 16 * 1024 * 1024,
            octets: 1024 * 1024 * 1024,
        }
    }
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
    tag: Option<Tag<'static>>,
    state: State,
    wants_read: bool,
    wants_write: Option<Vec<u8>>,
    fragments: VecDeque<Fragment>,
    codec: ResponseCodec,
    data: Vec<Data<'static>>,
    untagged: Vec<StatusBody<'static>>,
    skipped: Vec<Secret<Box<[u8]>>>,
    tagged: Option<Tagged<'static>>,
    bye: Option<Bye<'static>>,
    cr: Option<CommandContinuationRequest<'static>>,
    limbo_literal: Option<Vec<u8>>,
    done: bool,
    /// Bounds on the untagged responses collected before the completion.
    pub budget: ImapSendBudget,
    octets: usize,
    logout: bool,
}

impl<T: Encoder> ImapSend<T> {
    /// Builds a send serialising `message` through `encoder` and
    /// parsing its response, which ends on the tagged completion of the
    /// command tagged `tag`.
    ///
    /// Used for messages carrying no tag of their own, such as SASL
    /// continuation data or IDLE DONE, whose exchange ends on the
    /// completion of the command they continue.
    pub fn new(encoder: T, message: T::Message<'static>, tag: Tag<'static>) -> Self {
        let fragments = encoder.encode(&message).collect();

        Self {
            encoder,
            message: Some(message),
            untagged_command: None,
            tag_requested: false,
            tag: Some(tag),
            codec: ResponseCodec::new(),
            state: State::Serialize,
            wants_read: false,
            wants_write: None,
            fragments,
            data: Vec::new(),
            untagged: Vec::new(),
            skipped: Vec::new(),
            tagged: None,
            bye: None,
            cr: None,
            limbo_literal: None,
            done: false,
            budget: ImapSendBudget::default(),
            octets: 0,
            logout: false,
        }
    }

    /// Receive-only: skips serialisation and parses the response of a
    /// request whose bytes were written out of band.
    ///
    /// Used by the streamed APPEND literal; `message` is echoed back
    /// unchanged in the Ok output, and the exchange ends on the tagged
    /// completion of the command tagged `tag`.
    pub fn receive(message: T::Message<'static>, tag: Tag<'static>) -> Self
    where
        T: Default,
    {
        Self {
            encoder: T::default(),
            message: Some(message),
            untagged_command: None,
            tag_requested: false,
            tag: Some(tag),
            codec: ResponseCodec::new(),
            state: State::Read,
            wants_read: false,
            wants_write: None,
            fragments: VecDeque::new(),
            data: Vec::new(),
            untagged: Vec::new(),
            skipped: Vec::new(),
            tagged: None,
            bye: None,
            cr: None,
            limbo_literal: None,
            done: false,
            budget: ImapSendBudget::default(),
            octets: 0,
            logout: false,
        }
    }

    /// Charges one more collected response of `octets` to the budget.
    fn spend(&mut self, octets: usize) -> Result<(), ImapSendError> {
        let responses = self.data.len() + self.untagged.len() + self.skipped.len();
        self.octets = self.octets.saturating_add(octets);

        if responses >= self.budget.responses || self.octets > self.budget.octets {
            debug!("collected responses exceed the budget");
            return Err(ImapSendError::ResponseTooLong(self.budget));
        }

        Ok(())
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

                        self.tag = Some(tag.clone());

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
                    Some(&[]) if self.logout && self.bye.is_some() => {
                        self.done = true;
                        self.state = State::Deserialize;
                    }
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

                        let octets = fragmentizer.message_bytes().len();

                        match fragmentizer.decode_message(&self.codec) {
                            Ok(Response::Data(data)) => {
                                if let Err(err) = self.spend(octets) {
                                    return ImapSendResult::Err(err);
                                }

                                self.data.push(data.into_static());
                            }
                            Ok(Response::Status(Status::Untagged(status))) => {
                                if let Err(err) = self.spend(octets) {
                                    return ImapSendResult::Err(err);
                                }

                                self.untagged.push(status.into_static());
                            }
                            Ok(Response::Status(Status::Tagged(tagged)))
                                if Some(&tagged.tag) != self.tag.as_ref() =>
                            {
                                // NOTE: a completion of another command
                                // (late, or forged) must neither end
                                // this exchange nor lend it its status.
                                debug!("skipping tagged response of another command");
                                trace!("tag: {}", tagged.tag.as_ref());
                            }
                            Ok(Response::Status(Status::Tagged(tagged))) => {
                                self.tagged.replace(tagged.into_static());
                                self.done = true;
                            }
                            Ok(Response::Status(Status::Bye(bye))) => {
                                self.bye.replace(bye.into_static());
                                self.done = !self.logout;
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

                                            let skipped = Secret::new(bytes.into());

                                            if let Err(err) = self.spend(octets) {
                                                return ImapSendResult::Err(err);
                                            }

                                            self.skipped.push(skipped);
                                            continue;
                                        }

                                        if let Some(tagged) =
                                            decode_lossy_tagged(&self.codec, bytes)
                                        {
                                            if Some(&tagged.tag) != self.tag.as_ref() {
                                                debug!(
                                                    "skipping tagged response of another command"
                                                );
                                                trace!("tag: {}", tagged.tag.as_ref());
                                                continue;
                                            }

                                            debug!("read a completion holding 8-bit text");
                                            self.tagged.replace(tagged);
                                            self.done = true;
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
                            // NOTE: the tag is known once the message is.
                            tag: self.tag.take().unwrap(),
                            data: mem::take(&mut self.data),
                            untagged: mem::take(&mut self.untagged),
                            skipped: mem::take(&mut self.skipped),
                            tagged: self.tagged.take(),
                            bye: self.bye.take(),
                            continuation_request: self.cr.take(),
                        }));
                    }
                    None if self.limbo_literal.is_some() => {
                        self.state = match self.cr.take() {
                            Some(_) => State::Serialize,
                            None => State::Read,
                        };
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
        // NOTE: the BYE of a LOGOUT precedes its completion (RFC 3501
        // §6.1.3), so it does not end the exchange as it does elsewhere.
        let logout = matches!(body, CommandBody::Logout);

        Self {
            encoder: CommandCodec::new(),
            message: None,
            untagged_command: Some(UntaggedCommand {
                body,
                into_message: |command| command,
            }),
            tag_requested: false,
            tag: None,
            codec: ResponseCodec::new(),
            state: State::Tag,
            wants_read: false,
            wants_write: None,
            fragments: VecDeque::new(),
            data: Vec::new(),
            untagged: Vec::new(),
            skipped: Vec::new(),
            tagged: None,
            bye: None,
            cr: None,
            limbo_literal: None,
            done: false,
            budget: ImapSendBudget::default(),
            octets: 0,
            logout,
        }
    }
}

/// What ends the exchange of the command tagged `tag`, read from the
/// complete message in `fragmentizer`: its tagged completion, or a BYE.
///
/// A completion of another command and any other response give `None`.
/// Shared by the coroutines reading their response line by line.
pub(crate) fn decode_completion(
    fragmentizer: &Fragmentizer,
    codec: &ResponseCodec,
    tag: &Tag<'_>,
) -> Option<ImapCompletion> {
    let tagged = match fragmentizer.decode_message(codec) {
        Ok(Response::Status(Status::Tagged(tagged))) => tagged.into_static(),
        Ok(Response::Status(Status::Bye(bye))) => {
            return Some(ImapCompletion::Bye(bye.into_static()));
        }
        Ok(_) => return None,
        Err(_) => decode_lossy_tagged(codec, fragmentizer.message_bytes())?,
    };

    if tagged.tag != *tag {
        debug!("skipping tagged response of another command");
        trace!("tag: {}", tagged.tag.as_ref());
        return None;
    }

    Some(ImapCompletion::Tagged(tagged))
}

/// The tagged completion `bytes` hold when they only fail to decode for
/// the 8-bit bytes of its text, which IMAP4rev1 keeps ASCII but servers
/// send: it is decoded again with each of them read as `?`.
pub(crate) fn decode_lossy_tagged(codec: &ResponseCodec, bytes: &[u8]) -> Option<Tagged<'static>> {
    use imap_codec::decode::Decoder;

    let ascii: Vec<u8> = bytes
        .iter()
        .map(|&byte| if byte.is_ascii() { byte } else { b'?' })
        .collect();

    match codec.decode(&ascii) {
        Ok((_, Response::Status(Status::Tagged(tagged)))) => Some(tagged.into_static()),
        _ => None,
    }
}

/// The response ending an exchange read line by line.
pub(crate) enum ImapCompletion {
    /// The tagged completion of the command.
    Tagged(Tagged<'static>),
    /// The BYE closing the session.
    Bye(Bye<'static>),
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
    /// The tag of the command the exchange belongs to.
    pub tag: Tag<'static>,
    /// The untagged data responses collected during the exchange.
    pub data: Vec<Data<'static>>,
    /// The untagged status responses collected during the exchange.
    pub untagged: Vec<StatusBody<'static>>,
    /// The untagged responses that did not decode and were skipped, as
    /// raw bytes: data the result may be missing.
    pub skipped: Vec<Secret<Box<[u8]>>>,
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

    use imap_codec::imap_types::{
        core::Literal, extensions::binary::LiteralOrLiteral8, response::StatusKind,
    };

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

    #[test]
    fn foreign_tagged_completion_is_skipped() {
        let mut send = ImapSend::command(CommandBody::Noop);
        let mut frag = Fragmentizer::new(1024);

        assert!(matches!(
            send.resume(&mut frag, None),
            ImapSendResult::WantsTag
        ));
        assert!(matches!(
            send.resume(&mut frag, Some(b"A1")),
            ImapSendResult::WantsWrite(_)
        ));
        assert!(matches!(
            send.resume(&mut frag, None),
            ImapSendResult::WantsRead
        ));

        // NOTE: the foreign completion arrives alone, so that taking it
        // would end the exchange before the right one is read.
        let foreign = b"B9 NO not yours\r\n";
        assert!(matches!(
            send.resume(&mut frag, Some(foreign)),
            ImapSendResult::WantsRead
        ));

        let reply = b"A1 OK NOOP completed\r\n";
        let ImapSendResult::Ok(out) = send.resume(&mut frag, Some(reply)) else {
            panic!("expected Ok");
        };

        let tagged = out.tagged.expect("tagged completion");
        assert_eq!("A1", tagged.tag.as_ref());
        assert_eq!(StatusKind::Ok, tagged.body.kind);
    }

    /// Dovecot echoes a UTF-8 mailbox name in the text of a `NO`, which
    /// IMAP4rev1 keeps ASCII: the completion still ends the exchange.
    #[test]
    fn a_completion_holding_8bit_text_is_read() {
        let mut send = ImapSend::command(CommandBody::Noop);
        let mut frag = Fragmentizer::new(1024);

        send.resume(&mut frag, None);
        send.resume(&mut frag, Some(b"A1"));
        send.resume(&mut frag, None);

        let reply = "A1 NO [NONEXISTENT] Mailbox doesn't exist: Été\r\n";
        let ImapSendResult::Ok(out) = send.resume(&mut frag, Some(reply.as_bytes())) else {
            panic!("expected Ok");
        };

        let tagged = out.tagged.expect("tagged completion");
        assert_eq!(StatusKind::No, tagged.body.kind);
        assert!(tagged.body.text.as_ref().ends_with("exist: ??t??"));
    }

    #[test]
    fn a_foreign_completion_holding_8bit_text_is_skipped() {
        let mut send = ImapSend::command(CommandBody::Noop);
        let mut frag = Fragmentizer::new(1024);

        send.resume(&mut frag, None);
        send.resume(&mut frag, Some(b"A1"));
        send.resume(&mut frag, None);

        let foreign = "B9 NO [NONEXISTENT] Mailbox doesn't exist: Été\r\n";
        assert!(matches!(
            send.resume(&mut frag, Some(foreign.as_bytes())),
            ImapSendResult::WantsRead
        ));

        let reply = b"A1 OK NOOP completed\r\n";
        let ImapSendResult::Ok(out) = send.resume(&mut frag, Some(reply)) else {
            panic!("expected Ok");
        };

        let tagged = out.tagged.expect("tagged completion");
        assert_eq!(StatusKind::Ok, tagged.body.kind);
    }

    #[test]
    fn skipped_untagged_response_is_kept_in_output() {
        let mut send = ImapSend::command(CommandBody::Noop);
        let mut frag = Fragmentizer::new(1024);

        send.resume(&mut frag, None);
        send.resume(&mut frag, Some(b"A1"));
        send.resume(&mut frag, None);

        let line = b"* FLAGS (OIB-Seen-[Gmail]/All Mail)\r\n";
        let reply = [line.as_slice(), b"A1 OK NOOP completed\r\n"].concat();
        let ImapSendResult::Ok(out) = send.resume(&mut frag, Some(&reply)) else {
            panic!("expected Ok");
        };

        assert_eq!(1, out.skipped.len());
        assert_eq!(line, &**out.skipped[0].declassify());
    }

    #[test]
    fn responses_over_budget_return_too_long_error() {
        for budget in [
            ImapSendBudget {
                responses: 2,
                octets: usize::MAX,
            },
            ImapSendBudget {
                responses: usize::MAX,
                octets: 24,
            },
        ] {
            let mut send = ImapSend::command(CommandBody::Noop);
            send.budget = budget;
            let mut frag = Fragmentizer::new(1024);

            send.resume(&mut frag, None);
            send.resume(&mut frag, Some(b"A1"));
            send.resume(&mut frag, None);

            let within = b"* 1 EXISTS\r\n* 2 EXISTS\r\n";
            assert!(matches!(
                send.resume(&mut frag, Some(within)),
                ImapSendResult::WantsRead
            ));

            let ImapSendResult::Err(err) = send.resume(&mut frag, Some(b"* 3 EXISTS\r\n")) else {
                panic!("expected Err for {budget:?}");
            };
            let ImapSendError::ResponseTooLong(exceeded) = err else {
                panic!("expected ImapSendError::ResponseTooLong, got {err:?}");
            };
            assert_eq!(budget, exceeded);
        }
    }

    #[test]
    fn responses_filling_budget_are_collected() {
        let mut send = ImapSend::command(CommandBody::Noop);
        send.budget = ImapSendBudget {
            responses: 2,
            octets: 24,
        };
        let mut frag = Fragmentizer::new(1024);

        send.resume(&mut frag, None);
        send.resume(&mut frag, Some(b"A1"));
        send.resume(&mut frag, None);

        let reply = b"* 1 EXISTS\r\n* 2 EXISTS\r\nA1 OK NOOP completed\r\n";
        let ImapSendResult::Ok(out) = send.resume(&mut frag, Some(reply)) else {
            panic!("expected Ok");
        };
        assert_eq!(2, out.data.len());
    }

    #[test]
    fn sync_literal_waits_through_untagged_line() {
        let (mut send, mut frag) = append_waiting_for_continuation();

        let alert = b"* OK [ALERT] mailbox almost full\r\n";
        assert!(matches!(
            send.resume(&mut frag, Some(alert)),
            ImapSendResult::WantsRead
        ));

        let ImapSendResult::WantsWrite(bytes) = send.resume(&mut frag, Some(b"+ go\r\n")) else {
            panic!("expected WantsWrite");
        };
        assert_eq!("hi\r\n", str::from_utf8(&bytes).expect("utf8 literal"));
    }

    #[test]
    fn sync_literal_waits_through_split_continuation_request() {
        let (mut send, mut frag) = append_waiting_for_continuation();

        assert!(matches!(
            send.resume(&mut frag, Some(b"+ g")),
            ImapSendResult::WantsRead
        ));

        let ImapSendResult::WantsWrite(bytes) = send.resume(&mut frag, Some(b"o\r\n")) else {
            panic!("expected WantsWrite");
        };
        assert_eq!("hi\r\n", str::from_utf8(&bytes).expect("utf8 literal"));

        assert!(matches!(
            send.resume(&mut frag, None),
            ImapSendResult::WantsRead
        ));

        let reply = b"A1 OK APPEND completed\r\n";
        let ImapSendResult::Ok(out) = send.resume(&mut frag, Some(reply)) else {
            panic!("expected Ok");
        };

        let tagged = out.tagged.expect("tagged completion");
        assert_eq!(StatusKind::Ok, tagged.body.kind);
    }

    #[test]
    fn sync_literal_stays_unsent_on_split_no() {
        let (mut send, mut frag) = append_waiting_for_continuation();

        assert!(matches!(
            send.resume(&mut frag, Some(b"A1 NO [OVERQUOTA] quota exc")),
            ImapSendResult::WantsRead
        ));

        let ImapSendResult::Ok(out) = send.resume(&mut frag, Some(b"eeded\r\n")) else {
            panic!("expected Ok");
        };

        let tagged = out.tagged.expect("tagged completion");
        assert_eq!(StatusKind::No, tagged.body.kind);
    }

    fn append_waiting_for_continuation() -> (ImapSend<CommandCodec>, Fragmentizer) {
        let mut send = ImapSend::command(CommandBody::Append {
            mailbox: "INBOX".try_into().expect("valid mailbox"),
            flags: Vec::new(),
            date: None,
            message: LiteralOrLiteral8::Literal(Literal::unvalidated(b"hi".to_vec())),
        });
        let mut frag = Fragmentizer::new(1024);

        assert!(matches!(
            send.resume(&mut frag, None),
            ImapSendResult::WantsTag
        ));

        let ImapSendResult::WantsWrite(bytes) = send.resume(&mut frag, Some(b"A1")) else {
            panic!("expected WantsWrite");
        };
        assert_eq!(
            "A1 APPEND INBOX {2}\r\n",
            str::from_utf8(&bytes).expect("utf8 command")
        );

        assert!(matches!(
            send.resume(&mut frag, None),
            ImapSendResult::WantsRead
        ));

        (send, frag)
    }
}
