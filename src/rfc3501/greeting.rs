//! I/O-free coroutine to read the greeting from an IMAP server.

use core::mem;

use alloc::{boxed::Box, string::String, string::ToString, vec::Vec};

use imap_codec::{
    GreetingCodec,
    fragmentizer::{DecodeMessageError, FragmentInfo, Fragmentizer},
    imap_types::{
        IntoStatic,
        response::{Capability, Code, GreetingKind},
        secret::Secret,
        utils::escape_byte_string,
    },
};
use log::trace;
use thiserror::Error;

use crate::{coroutine::*, rfc3501::capability::*};

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

    #[error(transparent)]
    Capability(#[from] ImapCapabilityGetError),
}

/// Terminal success payload of [`ImapGreetingGet`].
pub struct ImapGreetingOk {
    pub capability: Vec<Capability<'static>>,
    pub pre_authenticated: bool,
}

enum State {
    Read,
    Deserialize,
    Capability(ImapCapabilityGet),
}

/// I/O-free coroutine to read the greeting from an IMAP server.
pub struct ImapGreetingGet {
    codec: GreetingCodec,
    state: State,
    wants_read: bool,
    observed: Vec<Capability<'static>>,
    pre_authenticated: bool,
    ensure_capabilities: bool,
}

impl ImapGreetingGet {
    /// Creates a new coroutine. When `ensure_capabilities` is true and
    /// the server did not piggyback a capability list on the greeting,
    /// the coroutine drives an extra `CAPABILITY` round-trip before
    /// completing.
    pub fn new(ensure_capabilities: bool) -> Self {
        Self {
            codec: GreetingCodec::new(),
            state: State::Read,
            wants_read: false,
            observed: Vec::new(),
            pre_authenticated: false,
            ensure_capabilities,
        }
    }
}

impl ImapCoroutine for ImapGreetingGet {
    type Output = ImapGreetingOk;
    type Error = ImapGreetingGetError;

    /// Advances the coroutine.
    ///
    /// Pass [`None`] when there is no data to provide (initial call).
    /// Pass `Some(data)` with bytes read from the stream after a
    /// [`ImapCoroutineState::WantsRead`]. Pass `Some(&[])` to signal
    /// EOF.
    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        mut arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Output, Self::Error> {
        loop {
            if mem::take(&mut self.wants_read) {
                return ImapCoroutineState::WantsRead;
            }

            match &mut self.state {
                State::Read => match arg.take() {
                    Some(&[]) => return ImapCoroutineState::Err(ImapGreetingGetError::Eof),
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
                        trace!("read greeting line: {}", escape_byte_string(bytes));

                        if !fragmentizer.is_message_complete() {
                            continue;
                        }

                        match fragmentizer.decode_message(&self.codec) {
                            Ok(greeting) if greeting.kind == GreetingKind::Bye => {
                                return ImapCoroutineState::Err(ImapGreetingGetError::Bye(
                                    greeting.text.to_string(),
                                ));
                            }
                            Ok(greeting) => {
                                self.pre_authenticated = greeting.kind == GreetingKind::PreAuth;

                                if let Some(Code::Capability(capability)) = greeting.code {
                                    self.observed = capability.into_static().into_iter().collect();
                                }

                                if self.ensure_capabilities && self.observed.is_empty() {
                                    self.state = State::Capability(ImapCapabilityGet::new());
                                    continue;
                                }

                                return ImapCoroutineState::Done(ImapGreetingOk {
                                    capability: mem::take(&mut self.observed),
                                    pre_authenticated: self.pre_authenticated,
                                });
                            }
                            Err(err) => {
                                let bytes = fragmentizer.message_bytes();
                                let bytes = Secret::new(bytes.into());
                                return ImapCoroutineState::Err(match err {
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
                                });
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
                State::Capability(coroutine) => match coroutine.resume(fragmentizer, arg.take()) {
                    ImapCoroutineState::WantsRead => return ImapCoroutineState::WantsRead,
                    ImapCoroutineState::WantsWrite(bytes) => {
                        return ImapCoroutineState::WantsWrite(bytes);
                    }
                    ImapCoroutineState::Done(capability) => {
                        return ImapCoroutineState::Done(ImapGreetingOk {
                            capability,
                            pre_authenticated: self.pre_authenticated,
                        });
                    }
                    ImapCoroutineState::Err(err) => {
                        return ImapCoroutineState::Err(err.into());
                    }
                },
            }
        }
    }
}
