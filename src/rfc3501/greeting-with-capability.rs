//! I/O-free coroutine to read greeting then capabilities of an IMAP
//! server.

use alloc::vec::Vec;

use thiserror::Error;

use crate::{
    context::ImapContext,
    rfc3501::{capability::*, greeting::*},
};

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum ImapGreetingWithCapabilityGetError {
    #[error(transparent)]
    Greeting(#[from] ImapGreetingGetError),
    #[error(transparent)]
    Capability(#[from] ImapCapabilityGetError),
}

enum State {
    Greeting(ImapGreetingGet),
    Capability(ImapCapabilityGet),
}

/// Output emitted when the coroutine terminates its progression.
pub enum ImapGreetingWithCapabilityGetResult {
    Ok {
        context: ImapContext,
    },
    WantsRead,
    WantsWrite(Vec<u8>),
    Err {
        context: ImapContext,
        err: ImapGreetingWithCapabilityGetError,
    },
}

/// I/O-free coroutine to read greeting then capabilities of an IMAP
/// server.
pub struct ImapGreetingWithCapabilityGet {
    state: State,
}

impl ImapGreetingWithCapabilityGet {
    /// Creates a new coroutine.
    pub fn new(context: ImapContext) -> Self {
        Self {
            state: State::Greeting(ImapGreetingGet::new(context)),
        }
    }

    /// Advances the coroutine.
    pub fn resume(&mut self, mut arg: Option<&[u8]>) -> ImapGreetingWithCapabilityGetResult {
        loop {
            match &mut self.state {
                State::Greeting(greeting) => {
                    let context = match greeting.resume(arg.take()) {
                        ImapGreetingGetResult::WantsRead => {
                            break ImapGreetingWithCapabilityGetResult::WantsRead;
                        }
                        ImapGreetingGetResult::Ok { context } => context,
                        ImapGreetingGetResult::Err { context, err } => {
                            break ImapGreetingWithCapabilityGetResult::Err {
                                context,
                                err: err.into(),
                            };
                        }
                    };

                    if !context.capability.is_empty() {
                        break ImapGreetingWithCapabilityGetResult::Ok { context };
                    }

                    self.state = State::Capability(ImapCapabilityGet::new(context));
                }
                State::Capability(capability) => match capability.resume(arg.take()) {
                    ImapCapabilityGetResult::WantsRead => {
                        break ImapGreetingWithCapabilityGetResult::WantsRead;
                    }
                    ImapCapabilityGetResult::WantsWrite(bytes) => {
                        break ImapGreetingWithCapabilityGetResult::WantsWrite(bytes);
                    }
                    ImapCapabilityGetResult::Ok { context } => {
                        break ImapGreetingWithCapabilityGetResult::Ok { context };
                    }
                    ImapCapabilityGetResult::Err { context, err } => {
                        break ImapGreetingWithCapabilityGetResult::Err {
                            context,
                            err: err.into(),
                        };
                    }
                },
            }
        }
    }
}
