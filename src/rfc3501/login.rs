//! I/O-free coroutine to login an IMAP mailbox.

use core::mem;

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        command::{Command, CommandBody},
        core::{AString, IString, NString, TagGenerator},
        error::ValidationError,
        response::{Capability, Code, Data, StatusKind, Tagged},
        secret::Secret,
    },
};
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;

use crate::coroutine::*;
use crate::{rfc2971::id::*, rfc3501::capability::*, send::*};

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

    #[error(transparent)]
    ServerId(#[from] ImapServerIdError),
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
    Id(ImapServerId),
}

/// I/O-free coroutine to login an IMAP mailbox.
pub struct ImapLogin {
    state: State,
    observed: Vec<Capability<'static>>,
    ensure_capabilities: bool,
    auto_id: Option<Vec<(IString<'static>, NString<'static>)>>,
}

impl ImapLogin {
    /// Creates a new coroutine. When `ensure_capabilities` is true and
    /// the server did not piggyback a capability list on the LOGIN
    /// tagged response, the coroutine drives an extra `CAPABILITY`
    /// round-trip before completing. When `auto_id` is [`Some`], runs
    /// an extra `ID` round-trip (RFC 2971) after authentication; an
    /// empty vec maps to `ID NIL`, a non-empty vec to `ID (key val
    /// …)`.
    pub fn new(
        params: ImapLoginParams,
        ensure_capabilities: bool,
        auto_id: Option<Vec<(IString<'static>, NString<'static>)>>,
    ) -> Self {
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
            auto_id,
        }
    }

    fn start_auto_id(&mut self) -> Option<State> {
        let params = self.auto_id.take()?;
        let wire = (!params.is_empty()).then_some(params);
        Some(State::Id(ImapServerId::new(wire)))
    }
}

impl ImapCoroutine for ImapLogin {
    type Yield = ImapYield;
    type Return = Result<Vec<Capability<'static>>, ImapLoginError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        mut arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        loop {
            match &mut self.state {
                State::Send(send) => {
                    let (bye, tagged, data) = match send.resume(fragmentizer, arg.take()) {
                        SendImapCommandResult::WantsRead => {
                            return ImapCoroutineState::Yielded(ImapYield::WantsRead);
                        }
                        SendImapCommandResult::WantsWrite(bytes) => {
                            return ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes));
                        }
                        SendImapCommandResult::Ok {
                            data, tagged, bye, ..
                        } => (bye, tagged, data),
                        SendImapCommandResult::Err(err) => {
                            return ImapCoroutineState::Complete(Err(err.into()));
                        }
                    };

                    if let Some(bye) = bye {
                        return ImapCoroutineState::Complete(Err(ImapLoginError::Bye(
                            bye.text.to_string(),
                        )));
                    }

                    let Some(Tagged { body, .. }) = tagged else {
                        return ImapCoroutineState::Complete(Err(ImapLoginError::MissingTagged));
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
                            return ImapCoroutineState::Complete(Err(ImapLoginError::No(
                                body.text.to_string(),
                            )));
                        }
                        StatusKind::Bad => {
                            return ImapCoroutineState::Complete(Err(ImapLoginError::Bad(
                                body.text.to_string(),
                            )));
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

                    if let Some(next) = self.start_auto_id() {
                        self.state = next;
                        continue;
                    }

                    return ImapCoroutineState::Complete(Ok(mem::take(&mut self.observed)));
                }
                State::Capability(coroutine) => match coroutine.resume(fragmentizer, arg.take()) {
                    ImapCoroutineState::Yielded(y) => return ImapCoroutineState::Yielded(y),
                    ImapCoroutineState::Complete(Ok(capability)) => {
                        self.observed = capability;
                        if let Some(next) = self.start_auto_id() {
                            self.state = next;
                            continue;
                        }
                        return ImapCoroutineState::Complete(Ok(mem::take(&mut self.observed)));
                    }
                    ImapCoroutineState::Complete(Err(err)) => {
                        return ImapCoroutineState::Complete(Err(err.into()));
                    }
                },
                State::Id(coroutine) => match coroutine.resume(fragmentizer, arg.take()) {
                    ImapCoroutineState::Yielded(y) => return ImapCoroutineState::Yielded(y),
                    ImapCoroutineState::Complete(Ok(_)) => {
                        return ImapCoroutineState::Complete(Ok(mem::take(&mut self.observed)));
                    }
                    ImapCoroutineState::Complete(Err(err)) => {
                        return ImapCoroutineState::Complete(Err(err.into()));
                    }
                },
            }
        }
    }
}
