//! I/O-free coroutine to authenticate an IMAP mailbox via the SASL
//! `LOGIN` mechanism.

use core::mem;

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    AuthenticateDataCodec, CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        auth::{AuthMechanism, AuthenticateData},
        command::{Command, CommandBody},
        core::TagGenerator,
        response::{Capability, Code, Data, StatusBody, StatusKind, Tagged},
    },
};
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;

use crate::coroutine::{ImapCoroutine, ImapCoroutineState};
use crate::{rfc3501::capability::*, send::*};

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum ImapAuthLoginError {
    #[error("Parse IMAP AUTHENTICATE LOGIN NO error: {0}")]
    No(String),
    #[error("Parse IMAP AUTHENTICATE LOGIN BAD error: {0}")]
    Bad(String),
    #[error("Parse IMAP AUTHENTICATE LOGIN BYE error: {0}")]
    Bye(String),

    #[error("No IMAP AUTHENTICATE tagged response returned by the server")]
    MissingTagged,

    #[error("Send IMAP AUTHENTICATE command error")]
    Send(#[from] SendImapCommandError),

    #[error("Parse IMAP AUTHENTICATE LOGIN response: unexpected continuation request")]
    UnexpectedContinuationRequest,
    #[error("Parse IMAP AUTHENTICATE LOGIN response: missing continuation request")]
    MissingContinuationRequest,

    #[error(transparent)]
    Capability(#[from] ImapCapabilityGetError),
}

pub struct ImapAuthLoginParams {
    username: String,
    password: String,
}

impl ImapAuthLoginParams {
    pub fn new(username: impl ToString, password: SecretString) -> Self {
        Self {
            username: username.to_string(),
            password: password.expose_secret().to_string(),
        }
    }
}

enum State {
    Send(SendImapCommand<CommandCodec>),
    ContinueUsername(SendImapCommand<AuthenticateDataCodec>),
    ContinuePassword(SendImapCommand<AuthenticateDataCodec>),
    Capability(ImapCapabilityGet),
}

/// I/O-free coroutine to authenticate an IMAP mailbox via the SASL
/// `LOGIN` mechanism.
pub struct ImapAuthLogin {
    state: State,
    username: String,
    password: String,
    observed: Vec<Capability<'static>>,
    ensure_capabilities: bool,
}

impl ImapAuthLogin {
    /// Creates a new coroutine.
    pub fn new(params: ImapAuthLoginParams, ensure_capabilities: bool) -> Self {
        let body = CommandBody::Authenticate {
            mechanism: AuthMechanism::Login,
            initial_response: None,
        };

        let mut tag = TagGenerator::new();
        // SAFETY: tag is always valid
        let command = Command::new(tag.generate(), body).unwrap();
        let send = SendImapCommand::new(CommandCodec::new(), command);

        Self {
            state: State::Send(send),
            username: params.username,
            password: params.password,
            observed: Vec::new(),
            ensure_capabilities,
        }
    }
}

impl ImapCoroutine for ImapAuthLogin {
    type Output = Vec<Capability<'static>>;
    type Error = ImapAuthLoginError;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        mut arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Output, Self::Error> {
        loop {
            match &mut self.state {
                State::Send(coroutine) => {
                    let (bye, continuation_request) = match coroutine
                        .resume(fragmentizer, arg.take())
                    {
                        SendImapCommandResult::WantsRead => return ImapCoroutineState::WantsRead,
                        SendImapCommandResult::WantsWrite(bytes) => {
                            return ImapCoroutineState::WantsWrite(bytes);
                        }
                        SendImapCommandResult::Ok {
                            bye,
                            continuation_request,
                            ..
                        } => (bye, continuation_request),
                        SendImapCommandResult::Err(err) => {
                            return ImapCoroutineState::Err(err.into());
                        }
                    };

                    if let Some(bye) = bye {
                        return ImapCoroutineState::Err(ImapAuthLoginError::Bye(
                            bye.text.to_string(),
                        ));
                    }

                    if continuation_request.is_none() {
                        return ImapCoroutineState::Err(
                            ImapAuthLoginError::MissingContinuationRequest,
                        );
                    }

                    let username = mem::take(&mut self.username).into_bytes();
                    let auth = AuthenticateData::r#continue(username);
                    let codec = AuthenticateDataCodec::new();
                    self.state = State::ContinueUsername(SendImapCommand::new(codec, auth));
                }
                State::ContinueUsername(coroutine) => {
                    let (bye, continuation_request) = match coroutine
                        .resume(fragmentizer, arg.take())
                    {
                        SendImapCommandResult::WantsRead => return ImapCoroutineState::WantsRead,
                        SendImapCommandResult::WantsWrite(bytes) => {
                            return ImapCoroutineState::WantsWrite(bytes);
                        }
                        SendImapCommandResult::Ok {
                            bye,
                            continuation_request,
                            ..
                        } => (bye, continuation_request),
                        SendImapCommandResult::Err(err) => {
                            return ImapCoroutineState::Err(err.into());
                        }
                    };

                    if let Some(bye) = bye {
                        return ImapCoroutineState::Err(ImapAuthLoginError::Bye(
                            bye.text.to_string(),
                        ));
                    }

                    if continuation_request.is_none() {
                        return ImapCoroutineState::Err(
                            ImapAuthLoginError::MissingContinuationRequest,
                        );
                    }

                    let password = mem::take(&mut self.password).into_bytes();
                    let auth = AuthenticateData::r#continue(password);
                    let codec = AuthenticateDataCodec::new();
                    self.state = State::ContinuePassword(SendImapCommand::new(codec, auth));
                }
                State::ContinuePassword(coroutine) => {
                    let (bye, continuation_request, tagged, data, untagged) = match coroutine
                        .resume(fragmentizer, arg.take())
                    {
                        SendImapCommandResult::WantsRead => return ImapCoroutineState::WantsRead,
                        SendImapCommandResult::WantsWrite(bytes) => {
                            return ImapCoroutineState::WantsWrite(bytes);
                        }
                        SendImapCommandResult::Ok {
                            bye,
                            continuation_request,
                            tagged,
                            data,
                            untagged,
                            ..
                        } => (bye, continuation_request, tagged, data, untagged),
                        SendImapCommandResult::Err(err) => {
                            return ImapCoroutineState::Err(err.into());
                        }
                    };

                    if let Some(bye) = bye {
                        return ImapCoroutineState::Err(ImapAuthLoginError::Bye(
                            bye.text.to_string(),
                        ));
                    }

                    if continuation_request.is_some() {
                        return ImapCoroutineState::Err(
                            ImapAuthLoginError::UnexpectedContinuationRequest,
                        );
                    }

                    match finish(tagged, data, untagged) {
                        Ok(capability) => {
                            self.observed = capability;
                            if self.ensure_capabilities && self.observed.is_empty() {
                                self.state = State::Capability(ImapCapabilityGet::new());
                                continue;
                            }
                            return ImapCoroutineState::Done(mem::take(&mut self.observed));
                        }
                        Err(err) => return ImapCoroutineState::Err(err),
                    }
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

fn finish(
    tagged: Option<Tagged<'static>>,
    data: Vec<Data<'static>>,
    untagged: Vec<StatusBody<'static>>,
) -> Result<Vec<Capability<'static>>, ImapAuthLoginError> {
    let Some(Tagged { body, .. }) = tagged else {
        return Err(ImapAuthLoginError::MissingTagged);
    };

    let code = match body.kind {
        StatusKind::Ok => body.code,
        StatusKind::No => return Err(ImapAuthLoginError::No(body.text.to_string())),
        StatusKind::Bad => return Err(ImapAuthLoginError::Bad(body.text.to_string())),
    };

    let mut new_capability = None;
    if let Some(Code::Capability(capability)) = code {
        new_capability.replace(capability);
    }
    for data in data {
        if let Data::Capability(capability) = data {
            new_capability.replace(capability);
        }
    }
    for StatusBody { code, .. } in untagged {
        if let Some(Code::Capability(capability)) = code {
            new_capability.replace(capability);
        }
    }

    Ok(new_capability
        .map(|c| c.into_iter().collect())
        .unwrap_or_default())
}
