//! I/O-free coroutine to login an IMAP mailbox.

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        command::{Command, CommandBody},
        core::{AString, TagGenerator},
        error::ValidationError,
        response::{Capability, Code, Data, StatusKind, Tagged},
        secret::Secret,
    },
};
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;

use crate::coroutine::{ImapCoroutine, ImapCoroutineState};
use crate::{rfc3501::capability::*, send::*};

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum ImapLoginError {
    #[error("Parse IMAP LOGIN NO error: {0}")]
    No(String),
    #[error("Parse IMAP LOGIN BAD error: {0}")]
    Bad(String),
    #[error("Parse IMAP LOGIN BYE error: {0}")]
    Bye(String),

    #[error("No IMAP LOGIN tagged response returned by the server")]
    MissingTagged,

    #[error("Send IMAP LOGIN command error")]
    Send(#[from] SendImapCommandError),

    #[error(transparent)]
    Capability(#[from] ImapCapabilityGetError),
}

pub struct ImapLoginParams {
    pub username: AString<'static>,
    pub password: Secret<AString<'static>>,
}

impl ImapLoginParams {
    pub fn new(username: impl ToString, password: SecretString) -> Result<Self, ValidationError> {
        Ok(Self {
            username: username.to_string().try_into()?,
            password: Secret::new(password.expose_secret().to_string().try_into()?),
        })
    }
}

enum State {
    Send(SendImapCommand<CommandCodec>),
    Capability(ImapCapabilityGet),
}

/// I/O-free coroutine to login an IMAP mailbox.
pub struct ImapLogin {
    state: State,
    observed: Vec<Capability<'static>>,
    ensure_capabilities: bool,
}

impl ImapLogin {
    /// Creates a new coroutine. When `ensure_capabilities` is true and
    /// the server did not piggyback a capability list on the LOGIN
    /// tagged response, the coroutine drives an extra `CAPABILITY`
    /// round-trip before completing.
    pub fn new(params: ImapLoginParams, ensure_capabilities: bool) -> Self {
        let login = CommandBody::Login {
            username: params.username,
            password: params.password,
        };

        let mut tag = TagGenerator::new();
        // SAFETY: tag is always valid
        let command = Command::new(tag.generate(), login).unwrap();
        let send = SendImapCommand::new(CommandCodec::new(), command);

        Self {
            state: State::Send(send),
            observed: Vec::new(),
            ensure_capabilities,
        }
    }
}

impl ImapCoroutine for ImapLogin {
    type Output = Vec<Capability<'static>>;
    type Error = ImapLoginError;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        mut arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Output, Self::Error> {
        loop {
            match &mut self.state {
                State::Send(send) => {
                    let (bye, tagged, data) = match send.resume(fragmentizer, arg.take()) {
                        SendImapCommandResult::WantsRead => return ImapCoroutineState::WantsRead,
                        SendImapCommandResult::WantsWrite(bytes) => {
                            return ImapCoroutineState::WantsWrite(bytes);
                        }
                        SendImapCommandResult::Ok {
                            data, tagged, bye, ..
                        } => (bye, tagged, data),
                        SendImapCommandResult::Err(err) => {
                            return ImapCoroutineState::Err(err.into());
                        }
                    };

                    if let Some(bye) = bye {
                        return ImapCoroutineState::Err(ImapLoginError::Bye(bye.text.to_string()));
                    }

                    let Some(Tagged { body, .. }) = tagged else {
                        return ImapCoroutineState::Err(ImapLoginError::MissingTagged);
                    };

                    let mut new_capability = None;
                    for data in data {
                        if let Data::Capability(capability) = data {
                            new_capability.replace(capability);
                        }
                    }

                    let code = match body.kind {
                        StatusKind::Ok => body.code,
                        StatusKind::No => {
                            return ImapCoroutineState::Err(ImapLoginError::No(
                                body.text.to_string(),
                            ));
                        }
                        StatusKind::Bad => {
                            return ImapCoroutineState::Err(ImapLoginError::Bad(
                                body.text.to_string(),
                            ));
                        }
                    };

                    if let Some(Code::Capability(capability)) = code {
                        new_capability.replace(capability);
                    }

                    if let Some(capability) = new_capability {
                        self.observed = capability.into_iter().collect();
                    }

                    if self.ensure_capabilities && self.observed.is_empty() {
                        self.state = State::Capability(ImapCapabilityGet::new());
                        continue;
                    }

                    return ImapCoroutineState::Done(core::mem::take(&mut self.observed));
                }
                State::Capability(coroutine) => match coroutine.resume(fragmentizer, arg.take()) {
                    ImapCoroutineState::WantsRead => return ImapCoroutineState::WantsRead,
                    ImapCoroutineState::WantsWrite(bytes) => {
                        return ImapCoroutineState::WantsWrite(bytes);
                    }
                    ImapCoroutineState::Done(capability) => {
                        return ImapCoroutineState::Done(capability);
                    }
                    ImapCoroutineState::Err(err) => {
                        return ImapCoroutineState::Err(err.into());
                    }
                },
            }
        }
    }
}
