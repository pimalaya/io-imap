//! I/O-free coroutine to watch IMAP mailbox changes using the IDLE
//! extension.

#[cfg(feature = "client")]
use core::time::Duration;
use core::{
    mem,
    sync::atomic::{AtomicBool, Ordering},
};

use alloc::{boxed::Box, string::String, string::ToString, sync::Arc, vec::Vec};

#[cfg(feature = "client")]
use std::time::Instant;

use imap_codec::{
    CommandCodec, IdleDoneCodec, ResponseCodec,
    fragmentizer::{DecodeMessageError, FragmentInfo, Fragmentizer},
    imap_types::{
        IntoStatic,
        command::{Command, CommandBody},
        core::TagGenerator,
        extensions::idle::IdleDone,
        response::{Bye, Data, Response, Status, StatusBody, StatusKind, Tagged},
        secret::Secret,
        utils::escape_byte_string,
    },
};
use log::trace;
use thiserror::Error;

use crate::coroutine::*;
use crate::send::*;

#[cfg(feature = "client")]
const IDLE_DEFAULT_TIMEOUT: Duration = Duration::from_secs(29);

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum ImapIdleError {
    #[error("IMAP IDLE unexpected OK: {0}")]
    Ok(String),
    #[error("IMAP IDLE missing continuation request")]
    ContinuationRequest,

    #[error("Reached unexpected EOF on IMAP stream")]
    Eof,

    #[error("Decode IMAP response error")]
    DecodingFailure(Secret<Box<[u8]>>),
    #[error("Parse IMAP response error: message is poisoned")]
    MessageIsPoisoned(Secret<Box<[u8]>>),
    #[error("Parse IMAP response error: message is too long")]
    MessageTooLong(Secret<Box<[u8]>>),

    #[error("Send IMAP DONE command error")]
    Done(#[from] SendImapCommandError),
    #[error("IMAP IDLE DONE NO error: {0}")]
    No(String),
    #[error("IMAP IDLE DONE BAD error: {0}")]
    Bad(String),
    #[error("IMAP IDLE DONE BYE error: {0}")]
    Bye(String),
    #[error("No IMAP IDLE DONE tagged response returned by the server")]
    Tagged,
}

/// One batch of unilateral untagged responses delivered during an
/// IDLE.
#[derive(Debug)]
pub struct ImapIdleEvent {
    pub untagged: Vec<StatusBody<'static>>,
    pub data: Vec<Data<'static>>,
}

/// Per-coroutine Yield: socket I/O step requests on one axis,
/// untagged-response batches on the other. The driver dispatches on
/// the variant: I/O variants pump the IMAP socket; [`Self::Event`] is
/// delivered to the caller (callback / channel / async stream).
#[derive(Debug)]
pub enum ImapIdleYield {
    /// Socket: read more bytes and feed them back on the next
    /// resume.
    WantsRead,
    /// Socket: write these bytes; the next resume typically takes
    /// `None`.
    WantsWrite(Vec<u8>),
    /// Domain: one batch of unilateral untagged responses received
    /// during the IDLE.
    Event(ImapIdleEvent),
}

enum State {
    /// Send the IDLE command and await the continuation request.
    Idle(SendImapCommand<CommandCodec>),
    /// Read unilateral responses until the shutdown flag is set or the
    /// internal refresh timeout elapses.
    Read,
    /// Send the DONE command and await the tagged response.
    Done(SendImapCommand<IdleDoneCodec>),
}

/// I/O-free coroutine to watch IMAP mailbox changes via IDLE.
///
/// Shutdown is cooperative: the caller flips the [`AtomicBool`]
/// handed to [`ImapIdle::new`], the coroutine reads it on its next
/// loop iteration and transitions from `Read` to `Done`, sending
/// `DONE` cleanly before exiting.
pub struct ImapIdle {
    tag: TagGenerator,
    state: State,
    wants_read: bool,
    codec: ResponseCodec,
    data: Vec<Data<'static>>,
    untagged: Vec<StatusBody<'static>>,
    bye: Option<Bye<'static>>,
    done: Arc<AtomicBool>,
    #[cfg(feature = "client")]
    timer: Option<Instant>,
}

impl ImapIdle {
    /// Creates a new coroutine.
    ///
    /// `done` is the shared shutdown flag: flip it to `true` to ask
    /// the coroutine to wind down at its next chance (sends `DONE`
    /// and completes with `Ok(())`). Pass `Arc::new(AtomicBool::new(false))`
    /// when no external shutdown is needed.
    pub fn new(done: Arc<AtomicBool>) -> Self {
        let mut tag = TagGenerator::new();
        // SAFETY: tag is always valid
        let command = Command::new(tag.generate(), CommandBody::Idle).unwrap();
        let state = State::Idle(SendImapCommand::new(CommandCodec::new(), command));

        Self {
            tag,
            state,
            wants_read: false,
            codec: ResponseCodec::new(),
            data: Vec::new(),
            untagged: Vec::new(),
            bye: None,
            done,
            #[cfg(feature = "client")]
            timer: None,
        }
    }
}

impl ImapCoroutine for ImapIdle {
    type Yield = ImapIdleYield;
    type Return = Result<(), ImapIdleError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        mut arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        #[cfg(feature = "client")]
        if self.timer.is_none() {
            self.timer = Some(Instant::now());
        }

        loop {
            if mem::take(&mut self.wants_read) {
                return ImapCoroutineState::Yielded(ImapIdleYield::WantsRead);
            }

            match &mut self.state {
                State::Idle(coroutine) => {
                    // An IMAP server can legally pack the
                    // continuation-request line and one or more
                    // unsolicited untagged responses into the same
                    // physical send, e.g. `+ idling\r\n* 10 FETCH …`
                    // when a flag change happens just before the
                    // server processes our `IDLE`. The inner
                    // `SendImapCommand` parses them all in one resume
                    // and returns them via `data` / `untagged`. If we
                    // dropped those vectors here, the unsolicited
                    // responses would be silently lost; we'd only
                    // learn about the change at the next IDLE / DONE
                    // refresh.
                    let (tagged, cr, bye, data, untagged) = match coroutine
                        .resume(fragmentizer, arg.take())
                    {
                        SendImapCommandResult::WantsRead => {
                            return ImapCoroutineState::Yielded(ImapIdleYield::WantsRead);
                        }
                        SendImapCommandResult::WantsWrite(bytes) => {
                            return ImapCoroutineState::Yielded(ImapIdleYield::WantsWrite(bytes));
                        }
                        SendImapCommandResult::Ok {
                            tagged,
                            continuation_request,
                            bye,
                            data,
                            untagged,
                            ..
                        } => (tagged, continuation_request, bye, data, untagged),
                        SendImapCommandResult::Err(err) => {
                            return ImapCoroutineState::Complete(Err(err.into()));
                        }
                    };

                    if let Some(bye) = bye {
                        return ImapCoroutineState::Complete(Err(ImapIdleError::Bye(
                            bye.text.to_string(),
                        )));
                    }

                    if let Some(Tagged { body, .. }) = tagged {
                        let text = body.text.to_string();
                        let err = match body.kind {
                            StatusKind::Ok => ImapIdleError::Ok(text),
                            StatusKind::No => ImapIdleError::No(text),
                            StatusKind::Bad => ImapIdleError::Bad(text),
                        };
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    if cr.is_none() {
                        return ImapCoroutineState::Complete(Err(
                            ImapIdleError::ContinuationRequest,
                        ));
                    }

                    // Unsolicited responses can piggy-back on the
                    // continuation-request frame (`+ idling\r\n*
                    // FETCH …`). The inner `SendImapCommand` already
                    // parsed them into `data` / `untagged`; surface
                    // them now so the caller sees the changes
                    // immediately instead of waiting for the next
                    // socket read.
                    self.state = State::Read;
                    if !data.is_empty() || !untagged.is_empty() {
                        return ImapCoroutineState::Yielded(ImapIdleYield::Event(ImapIdleEvent {
                            data,
                            untagged,
                        }));
                    }
                }
                State::Read => {
                    let done = self.done.load(Ordering::SeqCst);
                    #[cfg(feature = "client")]
                    let timed_out = self
                        .timer
                        .as_ref()
                        .map(|t| t.elapsed() >= IDLE_DEFAULT_TIMEOUT)
                        .unwrap_or(false);
                    #[cfg(not(feature = "client"))]
                    let timed_out = false;

                    if done || timed_out {
                        trace!("idle done: {done}");
                        trace!("idle timed out: {timed_out}");
                        self.state =
                            State::Done(SendImapCommand::new(IdleDoneCodec::new(), IdleDone));
                        continue;
                    }

                    match arg.take() {
                        Some(&[]) => {
                            return ImapCoroutineState::Complete(Err(ImapIdleError::Eof));
                        }
                        Some(data) => {
                            trace!("read bytes: {}", escape_byte_string(data));
                            fragmentizer.enqueue_bytes(data);
                        }
                        None => {
                            self.wants_read = true;
                            continue;
                        }
                    }

                    loop {
                        match fragmentizer.progress() {
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
                                    Ok(Response::Status(Status::Tagged(_))) => {
                                        // ignore tagged
                                    }
                                    Ok(Response::Status(Status::Bye(bye))) => {
                                        self.bye.replace(bye.into_static());
                                    }
                                    Ok(Response::CommandContinuationRequest(_)) => {
                                        // ignore continuation request
                                    }
                                    Err(decode_err) => {
                                        let bytes = fragmentizer.message_bytes();
                                        let bytes = Secret::new(bytes.into());
                                        let err = match decode_err {
                                            DecodeMessageError::DecodingFailure(_)
                                            | DecodeMessageError::DecodingRemainder { .. } => {
                                                ImapIdleError::DecodingFailure(bytes)
                                            }
                                            DecodeMessageError::MessageTooLong { .. } => {
                                                ImapIdleError::MessageTooLong(bytes)
                                            }
                                            DecodeMessageError::MessagePoisoned { .. } => {
                                                ImapIdleError::MessageIsPoisoned(bytes)
                                            }
                                        };
                                        return ImapCoroutineState::Complete(Err(err));
                                    }
                                }
                            }
                            Some(info @ FragmentInfo::Literal { .. }) => {
                                let bytes = fragmentizer.fragment_bytes(info);
                                trace!("read literal fragment ({} bytes)", bytes.len());
                            }
                            None => {
                                return ImapCoroutineState::Yielded(ImapIdleYield::Event(
                                    ImapIdleEvent {
                                        data: mem::take(&mut self.data),
                                        untagged: mem::take(&mut self.untagged),
                                    },
                                ));
                            }
                        }
                    }
                }
                State::Done(coroutine) => {
                    let (tagged, bye) = match coroutine.resume(fragmentizer, arg.take()) {
                        SendImapCommandResult::WantsRead => {
                            return ImapCoroutineState::Yielded(ImapIdleYield::WantsRead);
                        }
                        SendImapCommandResult::WantsWrite(bytes) => {
                            return ImapCoroutineState::Yielded(ImapIdleYield::WantsWrite(bytes));
                        }
                        SendImapCommandResult::Ok { tagged, bye, .. } => (tagged, bye),
                        SendImapCommandResult::Err(err) => {
                            return ImapCoroutineState::Complete(Err(err.into()));
                        }
                    };

                    if let Some(bye) = bye {
                        return ImapCoroutineState::Complete(Err(ImapIdleError::Bye(
                            bye.text.to_string(),
                        )));
                    }

                    let Some(Tagged { body, .. }) = tagged else {
                        return ImapCoroutineState::Complete(Err(ImapIdleError::Tagged));
                    };

                    #[cfg(feature = "client")]
                    let timed_out = self
                        .timer
                        .take()
                        .map(|t| t.elapsed() >= IDLE_DEFAULT_TIMEOUT)
                        .unwrap_or(false);
                    #[cfg(not(feature = "client"))]
                    let timed_out = false;

                    return match body.kind {
                        StatusKind::Ok if timed_out => {
                            trace!("reached timeout, starting a new IDLE command");
                            // SAFETY: tag is always valid
                            let command =
                                Command::new(self.tag.generate(), CommandBody::Idle).unwrap();
                            self.state =
                                State::Idle(SendImapCommand::new(CommandCodec::new(), command));
                            continue;
                        }
                        StatusKind::Ok => ImapCoroutineState::Complete(Ok(())),
                        StatusKind::No => ImapCoroutineState::Complete(Err(ImapIdleError::No(
                            body.text.to_string(),
                        ))),
                        StatusKind::Bad => ImapCoroutineState::Complete(Err(ImapIdleError::Bad(
                            body.text.to_string(),
                        ))),
                    };
                }
            }
        }
    }
}
