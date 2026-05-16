//! I/O-free coroutine to read the greeting from an IMAP server.

use core::mem;

use alloc::{boxed::Box, string::String, string::ToString};

use imap_codec::{
    GreetingCodec,
    fragmentizer::{DecodeMessageError, FragmentInfo, Fragmentizer},
    imap_types::{
        IntoStatic,
        response::{Code, GreetingKind},
        secret::Secret,
        utils::escape_byte_string,
    },
};
use log::trace;
use thiserror::Error;

use crate::context::ImapContext;

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum ImapGreetingGetError {
    #[error("Reached unexpected EOF on IMAP stream")]
    Eof,

    #[error("Parse IMAP greeting error")]
    DecodingFailure(Secret<Box<[u8]>>),
    #[error("Parse IMAP greeting poisoned error")]
    MessageIsPoisoned(Secret<Box<[u8]>>),
    #[error("Parse IMAP greeting too long error")]
    MessageTooLong(Secret<Box<[u8]>>),

    #[error("Parse IMAP greeting BYE error: {0}")]
    Bye(String),
}

/// Output emitted when the coroutine terminates its progression.
pub enum ImapGreetingGetResult {
    Ok {
        context: ImapContext,
    },
    WantsRead,
    Err {
        context: ImapContext,
        err: ImapGreetingGetError,
    },
}

enum State {
    Read,
    Deserialize,
}

/// I/O-free coroutine to read the greeting from an IMAP server.
pub struct ImapGreetingGet {
    context: Option<ImapContext>,
    codec: GreetingCodec,
    state: State,
    wants_read: bool,
    fragmentizer: Fragmentizer,
}

impl ImapGreetingGet {
    /// Creates a new coroutine.
    pub fn new(context: ImapContext) -> Self {
        Self {
            context: Some(context),
            codec: GreetingCodec::new(),
            state: State::Read,
            wants_read: false,
            fragmentizer: Fragmentizer::without_max_message_size(),
        }
    }

    /// Advances the coroutine.
    ///
    /// Pass [`None`] when there is no data to provide (initial call).
    /// Pass `Some(data)` with bytes read from the stream after a
    /// [`ImapGreetingGetResult::WantsRead`]. Pass `Some(&[])` to signal
    /// EOF.
    pub fn resume(&mut self, mut arg: Option<&[u8]>) -> ImapGreetingGetResult {
        loop {
            if mem::take(&mut self.wants_read) {
                return ImapGreetingGetResult::WantsRead;
            }

            match self.state {
                State::Read => match arg.take() {
                    Some(&[]) => {
                        // SAFETY: context always exists during a resume cycle
                        let context = self.context.take().unwrap();
                        return ImapGreetingGetResult::Err {
                            context,
                            err: ImapGreetingGetError::Eof,
                        };
                    }
                    Some(data) => {
                        trace!("read bytes: {}", escape_byte_string(data));
                        self.fragmentizer.enqueue_bytes(data);
                        self.state = State::Deserialize;
                    }
                    None => {
                        self.wants_read = true;
                    }
                },
                State::Deserialize => match self.fragmentizer.progress() {
                    Some(info @ FragmentInfo::Line { .. }) => {
                        let bytes = self.fragmentizer.fragment_bytes(info);
                        trace!("read greeting line: {}", escape_byte_string(bytes));

                        if !self.fragmentizer.is_message_complete() {
                            continue;
                        }

                        match self.fragmentizer.decode_message(&self.codec) {
                            Ok(greeting) if greeting.kind == GreetingKind::Bye => {
                                let context = self.context.take().unwrap();
                                let err = ImapGreetingGetError::Bye(greeting.text.to_string());
                                return ImapGreetingGetResult::Err { context, err };
                            }
                            Ok(greeting) => {
                                let mut context = self.context.take().unwrap();

                                context.authenticated = greeting.kind == GreetingKind::PreAuth;

                                if let Some(Code::Capability(capability)) = greeting.code {
                                    context.capability =
                                        capability.into_static().into_iter().collect();
                                }

                                return ImapGreetingGetResult::Ok { context };
                            }
                            Err(err) => {
                                let bytes = self.fragmentizer.message_bytes();
                                let bytes = Secret::new(bytes.into());
                                let context = self.context.take().unwrap();
                                let err = match err {
                                    DecodeMessageError::DecodingFailure(_)
                                    | DecodeMessageError::DecodingRemainder { .. } => {
                                        ImapGreetingGetError::DecodingFailure(bytes)
                                    }
                                    DecodeMessageError::MessageTooLong { .. } => {
                                        ImapGreetingGetError::MessageTooLong(bytes)
                                    }
                                    DecodeMessageError::MessagePoisoned { .. } => {
                                        ImapGreetingGetError::MessageIsPoisoned(bytes)
                                    }
                                };
                                return ImapGreetingGetResult::Err { context, err };
                            }
                        }
                    }
                    Some(FragmentInfo::Literal { .. }) => {
                        // not used by client
                        unreachable!();
                    }
                    None => {
                        self.state = State::Read;
                    }
                },
            }
        }
    }
}
