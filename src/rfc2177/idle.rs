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
    fragmentizer::{DecodeMessageError, FragmentInfo},
    imap_types::{
        IntoStatic,
        command::{Command, CommandBody},
        extensions::idle::IdleDone,
        response::{Bye, Data, Response, Status, StatusBody, StatusKind, Tagged},
        secret::Secret,
        utils::escape_byte_string,
    },
};
use log::trace;
use thiserror::Error;

use crate::{context::ImapContext, send::*};

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

/// Output emitted when the coroutine terminates its progression.
pub enum ImapIdleResult {
    /// A batch of unilateral untagged responses arrived during the
    /// IDLE.
    Data {
        untagged: Vec<StatusBody<'static>>,
        data: Vec<Data<'static>>,
    },
    Ok {
        context: ImapContext,
    },
    WantsRead,
    WantsWrite(Vec<u8>),
    Err {
        context: ImapContext,
        err: ImapIdleError,
    },
}

enum State {
    /// Send the IDLE command and await the continuation request.
    Idle(SendImapCommand<CommandCodec>),
    /// Read unilateral responses until [`ImapIdleDone::done`] is set
    /// or the timeout elapses.
    Read,
    /// Send the DONE command and await the tagged response.
    Done(SendImapCommand<IdleDoneCodec>),
}

/// I/O-free coroutine to watch IMAP mailbox changes via IDLE.
pub struct ImapIdle {
    context: Option<ImapContext>,
    state: State,
    wants_read: bool,
    codec: ResponseCodec,
    data: Vec<Data<'static>>,
    untagged: Vec<StatusBody<'static>>,
    bye: Option<Bye<'static>>,
    idle: ImapIdleDone,
    #[cfg(feature = "client")]
    timer: Option<Instant>,
}

impl ImapIdle {
    /// Creates a new coroutine.
    pub fn new(mut context: ImapContext, done: ImapIdleDone) -> Self {
        // SAFETY: tag is always valid
        let command = Command::new(context.generate_tag(), CommandBody::Idle).unwrap();
        let state = State::Idle(SendImapCommand::new(context, CommandCodec::new(), command));

        Self {
            context: None, // context is owned by the state
            state,
            wants_read: false,
            codec: ResponseCodec::new(),
            data: Vec::new(),
            untagged: Vec::new(),
            bye: None,
            idle: done,
            #[cfg(feature = "client")]
            timer: None,
        }
    }

    /// Advances the coroutine.
    pub fn resume(&mut self, mut arg: Option<&[u8]>) -> ImapIdleResult {
        #[cfg(feature = "client")]
        if self.timer.is_none() {
            self.timer = Some(Instant::now());
        }

        loop {
            if mem::take(&mut self.wants_read) {
                return ImapIdleResult::WantsRead;
            }

            match &mut self.state {
                State::Idle(coroutine) => {
                    let (context, tagged, cr, bye) = match coroutine.resume(arg.take()) {
                        SendImapCommandResult::WantsRead => return ImapIdleResult::WantsRead,
                        SendImapCommandResult::WantsWrite(bytes) => {
                            return ImapIdleResult::WantsWrite(bytes);
                        }
                        SendImapCommandResult::Ok {
                            context,
                            tagged,
                            continuation_request,
                            bye,
                            ..
                        } => (context, tagged, continuation_request, bye),
                        SendImapCommandResult::Err { context, err } => {
                            return ImapIdleResult::Err {
                                context,
                                err: err.into(),
                            };
                        }
                    };

                    if let Some(bye) = bye {
                        let err = ImapIdleError::Bye(bye.text.to_string());
                        return ImapIdleResult::Err { context, err };
                    }

                    if let Some(Tagged { body, .. }) = tagged {
                        let text = body.text.to_string();
                        let err = match body.kind {
                            StatusKind::Ok => ImapIdleError::Ok(text),
                            StatusKind::No => ImapIdleError::No(text),
                            StatusKind::Bad => ImapIdleError::Bad(text),
                        };
                        return ImapIdleResult::Err { context, err };
                    }

                    if cr.is_none() {
                        let err = ImapIdleError::ContinuationRequest;
                        return ImapIdleResult::Err { context, err };
                    }

                    self.context = Some(context);
                    self.state = State::Read;
                }
                State::Read => {
                    let done = self.idle.is_done();
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
                        // SAFETY: context is set when entering Read state
                        let context = self.context.take().unwrap();
                        self.state = State::Done(SendImapCommand::new(
                            context,
                            IdleDoneCodec::new(),
                            IdleDone,
                        ));
                        continue;
                    }

                    match arg.take() {
                        Some(&[]) => {
                            // SAFETY: context is set when entering Read state
                            let context = self.context.take().unwrap();
                            return ImapIdleResult::Err {
                                context,
                                err: ImapIdleError::Eof,
                            };
                        }
                        Some(data) => {
                            // SAFETY: context is set when entering Read state
                            let context = self.context.as_mut().unwrap();
                            trace!("read bytes: {}", escape_byte_string(data));
                            context.fragmentizer.enqueue_bytes(data);
                        }
                        None => {
                            self.wants_read = true;
                            continue;
                        }
                    }

                    // SAFETY: context is set when entering Read state
                    let context = self.context.as_mut().unwrap();

                    loop {
                        match context.fragmentizer.progress() {
                            Some(info @ FragmentInfo::Line { .. }) => {
                                let bytes = context.fragmentizer.fragment_bytes(info);
                                trace!("read line fragment: {}", escape_byte_string(bytes));

                                if !context.fragmentizer.is_message_complete() {
                                    continue;
                                }

                                match context.fragmentizer.decode_message(&self.codec) {
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
                                        let bytes = context.fragmentizer.message_bytes();
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
                                        let context = self.context.take().unwrap();
                                        return ImapIdleResult::Err { context, err };
                                    }
                                }
                            }
                            Some(info @ FragmentInfo::Literal { .. }) => {
                                let bytes = context.fragmentizer.fragment_bytes(info);
                                trace!("read literal fragment ({} bytes)", bytes.len());
                            }
                            None => {
                                return ImapIdleResult::Data {
                                    data: mem::take(&mut self.data),
                                    untagged: mem::take(&mut self.untagged),
                                };
                            }
                        }
                    }
                }
                State::Done(coroutine) => {
                    let (mut context, tagged, bye) = match coroutine.resume(arg.take()) {
                        SendImapCommandResult::WantsRead => return ImapIdleResult::WantsRead,
                        SendImapCommandResult::WantsWrite(bytes) => {
                            return ImapIdleResult::WantsWrite(bytes);
                        }
                        SendImapCommandResult::Ok {
                            context,
                            tagged,
                            bye,
                            ..
                        } => (context, tagged, bye),
                        SendImapCommandResult::Err { context, err } => {
                            return ImapIdleResult::Err {
                                context,
                                err: err.into(),
                            };
                        }
                    };

                    if let Some(bye) = bye {
                        let err = ImapIdleError::Bye(bye.text.to_string());
                        return ImapIdleResult::Err { context, err };
                    }

                    let Some(Tagged { body, .. }) = tagged else {
                        let err = ImapIdleError::Tagged;
                        return ImapIdleResult::Err { context, err };
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
                                Command::new(context.generate_tag(), CommandBody::Idle).unwrap();
                            self.state = State::Idle(SendImapCommand::new(
                                context,
                                CommandCodec::new(),
                                command,
                            ));
                            continue;
                        }
                        StatusKind::Ok => ImapIdleResult::Ok { context },
                        StatusKind::No => {
                            let err = ImapIdleError::No(body.text.to_string());
                            ImapIdleResult::Err { context, err }
                        }
                        StatusKind::Bad => {
                            let err = ImapIdleError::Bad(body.text.to_string());
                            ImapIdleResult::Err { context, err }
                        }
                    };
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct ImapIdleDone(Arc<AtomicBool>);

impl ImapIdleDone {
    pub fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    pub fn reset(&self) {
        self.0.store(false, Ordering::SeqCst);
    }

    pub fn done(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn is_done(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

impl Default for ImapIdleDone {
    fn default() -> Self {
        Self::new()
    }
}
