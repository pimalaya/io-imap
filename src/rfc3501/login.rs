//! I/O-free coroutine to login an IMAP mailbox.

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    imap_types::{
        command::{Command, CommandBody},
        core::AString,
        error::ValidationError,
        response::{Code, Data, StatusKind, Tagged},
        secret::Secret,
    },
};
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;

use crate::{context::ImapContext, rfc3501::capability::*, send::*};

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

/// Output emitted when the coroutine terminates its progression.
pub enum ImapLoginResult {
    Ok {
        context: ImapContext,
    },
    WantsRead,
    WantsWrite(Vec<u8>),
    Err {
        context: ImapContext,
        err: ImapLoginError,
    },
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
    ensure_capabilities: bool,
}

impl ImapLogin {
    /// Creates a new coroutine. When `ensure_capabilities` is true and the
    /// server did not piggyback a capability list on the LOGIN tagged
    /// response, the coroutine drives an extra `CAPABILITY` round-trip
    /// before completing.
    pub fn new(
        mut context: ImapContext,
        params: ImapLoginParams,
        ensure_capabilities: bool,
    ) -> Self {
        let login = CommandBody::Login {
            username: params.username,
            password: params.password,
        };

        // SAFETY: tag is always valid
        let command = Command::new(context.generate_tag(), login).unwrap();
        let send = SendImapCommand::new(context, CommandCodec::new(), command);

        Self {
            state: State::Send(send),
            ensure_capabilities,
        }
    }

    /// Advances the coroutine.
    pub fn resume(&mut self, mut arg: Option<&[u8]>) -> ImapLoginResult {
        loop {
            match &mut self.state {
                State::Send(send) => {
                    let (mut context, bye, tagged, data) = match send.resume(arg.take()) {
                        SendImapCommandResult::WantsRead => {
                            break ImapLoginResult::WantsRead;
                        }
                        SendImapCommandResult::WantsWrite(bytes) => {
                            break ImapLoginResult::WantsWrite(bytes);
                        }
                        SendImapCommandResult::Ok {
                            context,
                            data,
                            tagged,
                            bye,
                            ..
                        } => (context, bye, tagged, data),
                        SendImapCommandResult::Err { context, err } => {
                            break ImapLoginResult::Err {
                                context,
                                err: err.into(),
                            };
                        }
                    };

                    if let Some(bye) = bye {
                        let err = ImapLoginError::Bye(bye.text.to_string());
                        return ImapLoginResult::Err { context, err };
                    }

                    let Some(Tagged { body, .. }) = tagged else {
                        let err = ImapLoginError::MissingTagged;
                        return ImapLoginResult::Err { context, err };
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
                            let err = ImapLoginError::No(body.text.to_string());
                            return ImapLoginResult::Err { context, err };
                        }
                        StatusKind::Bad => {
                            let err = ImapLoginError::Bad(body.text.to_string());
                            return ImapLoginResult::Err { context, err };
                        }
                    };

                    if let Some(Code::Capability(capability)) = code {
                        new_capability.replace(capability);
                    }

                    if let Some(capability) = new_capability {
                        context.capability = capability.into_iter().collect();
                    }

                    context.authenticated = true;

                    if self.ensure_capabilities && context.capability.is_empty() {
                        self.state = State::Capability(ImapCapabilityGet::new(context));
                        continue;
                    }

                    return ImapLoginResult::Ok { context };
                }
                State::Capability(coroutine) => match coroutine.resume(arg.take()) {
                    ImapCapabilityGetResult::WantsRead => {
                        break ImapLoginResult::WantsRead;
                    }
                    ImapCapabilityGetResult::WantsWrite(bytes) => {
                        break ImapLoginResult::WantsWrite(bytes);
                    }
                    ImapCapabilityGetResult::Ok { context } => {
                        break ImapLoginResult::Ok { context };
                    }
                    ImapCapabilityGetResult::Err { context, err } => {
                        break ImapLoginResult::Err {
                            context,
                            err: err.into(),
                        };
                    }
                },
            }
        }
    }
}
