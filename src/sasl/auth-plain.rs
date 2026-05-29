//! I/O-free coroutine to authenticate an IMAP mailbox via PLAIN.

use core::mem;

use alloc::{borrow::ToOwned, string::String, string::ToString, vec::Vec};

use imap_codec::{
    AuthenticateDataCodec, CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        auth::{AuthMechanism, AuthenticateData},
        command::{Command, CommandBody},
        core::TagGenerator,
        response::{Capability, Code, Data, StatusBody, StatusKind, Tagged},
        secret::Secret,
    },
};
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;

use crate::coroutine::*;
use crate::{rfc3501::capability::*, send::*};

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum ImapAuthPlainError {
    #[error("Parse IMAP AUTHENTICATE NO error: {0}")]
    No(String),
    #[error("Parse IMAP AUTHENTICATE BAD error: {0}")]
    Bad(String),
    #[error("Parse IMAP AUTHENTICATE BYE error: {0}")]
    Bye(String),

    #[error("No IMAP AUTHENTICATE tagged response returned by the server")]
    MissingTagged,

    #[error("Send IMAP AUTHENTICATE command error")]
    Send(#[from] SendImapCommandError),

    #[error("Parse IMAP AUTHENTICATE response: unexpected continuation request")]
    UnexpectedContinuationRequest,
    #[error("Parse IMAP AUTHENTICATE response: missing continuation request")]
    MissingContinuationRequest,

    #[error(transparent)]
    Capability(#[from] ImapCapabilityGetError),
}

pub struct ImapAuthPlainParams {
    authzid: Option<String>,
    authcid: String,
    passwd: Secret<String>,
    ir: bool,
}

impl ImapAuthPlainParams {
    pub fn new(
        authzid: Option<impl ToString>,
        authcid: impl ToString,
        passwd: SecretString,
        ir: bool,
    ) -> Self {
        Self {
            authzid: authzid.map(|authzid| authzid.to_string()),
            authcid: authcid.to_string(),
            passwd: passwd.expose_secret().to_string().into(),
            ir,
        }
    }
}

enum State {
    Send(SendImapCommand<CommandCodec>),
    Continue(SendImapCommand<AuthenticateDataCodec>),
    Capability(ImapCapabilityGet),
}

/// I/O-free coroutine to authenticate an IMAP mailbox via PLAIN.
pub struct ImapAuthPlain {
    state: State,
    payload: String,
    ir: bool,
    observed: Vec<Capability<'static>>,
    ensure_capabilities: bool,
}

impl ImapAuthPlain {
    /// Creates a new coroutine.
    pub fn new(params: ImapAuthPlainParams, ensure_capabilities: bool) -> Self {
        let cid = params.authcid;
        let pass = params.passwd.declassify();

        let payload = match params.authzid {
            Some(zid) => format!("\x00{zid}\x00{cid}\x00{pass}"),
            None => format!("\x00{cid}\x00{pass}"),
        };

        let initial_response = if params.ir {
            Some(Secret::new(payload.as_bytes().to_owned().into()))
        } else {
            None
        };

        let plain = CommandBody::Authenticate {
            mechanism: AuthMechanism::Plain,
            initial_response,
        };

        let mut tag = TagGenerator::new();
        // SAFETY: tag is always valid
        let command = Command::new(tag.generate(), plain).unwrap();
        let send = SendImapCommand::new(CommandCodec::new(), command);

        Self {
            state: State::Send(send),
            payload,
            ir: params.ir,
            observed: Vec::new(),
            ensure_capabilities,
        }
    }
}

impl ImapCoroutine for ImapAuthPlain {
    type Yield = ImapYield;
    type Return = Result<Vec<Capability<'static>>, ImapAuthPlainError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        mut arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        loop {
            match &mut self.state {
                State::Send(coroutine) => {
                    let (bye, continuation_request, tagged, data, untagged) =
                        match coroutine.resume(fragmentizer, arg.take()) {
                            SendImapCommandResult::WantsRead => {
                                return ImapCoroutineState::Yielded(ImapYield::WantsRead);
                            }
                            SendImapCommandResult::WantsWrite(bytes) => {
                                return ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes));
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
                                return ImapCoroutineState::Complete(Err(err.into()));
                            }
                        };

                    if let Some(bye) = bye {
                        return ImapCoroutineState::Complete(Err(ImapAuthPlainError::Bye(
                            bye.text.to_string(),
                        )));
                    }

                    if continuation_request.is_some() {
                        if self.ir {
                            return ImapCoroutineState::Complete(Err(
                                ImapAuthPlainError::UnexpectedContinuationRequest,
                            ));
                        }

                        let payload = mem::take(&mut self.payload).into_bytes();
                        let auth = AuthenticateData::r#continue(payload);
                        let codec = AuthenticateDataCodec::new();
                        self.state = State::Continue(SendImapCommand::new(codec, auth));
                        continue;
                    }

                    if !self.ir {
                        return ImapCoroutineState::Complete(Err(
                            ImapAuthPlainError::MissingContinuationRequest,
                        ));
                    }

                    match finish(tagged, data, untagged) {
                        Ok(capability) => {
                            self.observed = capability;
                            if self.ensure_capabilities && self.observed.is_empty() {
                                self.state = State::Capability(ImapCapabilityGet::new());
                                continue;
                            }
                            return ImapCoroutineState::Complete(Ok(mem::take(&mut self.observed)));
                        }
                        Err(err) => return ImapCoroutineState::Complete(Err(err)),
                    }
                }
                State::Continue(coroutine) => {
                    let (bye, continuation_request, tagged, data, untagged) =
                        match coroutine.resume(fragmentizer, arg.take()) {
                            SendImapCommandResult::WantsRead => {
                                return ImapCoroutineState::Yielded(ImapYield::WantsRead);
                            }
                            SendImapCommandResult::WantsWrite(bytes) => {
                                return ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes));
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
                                return ImapCoroutineState::Complete(Err(err.into()));
                            }
                        };

                    if let Some(bye) = bye {
                        return ImapCoroutineState::Complete(Err(ImapAuthPlainError::Bye(
                            bye.text.to_string(),
                        )));
                    }

                    if continuation_request.is_some() {
                        return ImapCoroutineState::Complete(Err(
                            ImapAuthPlainError::UnexpectedContinuationRequest,
                        ));
                    }

                    match finish(tagged, data, untagged) {
                        Ok(capability) => {
                            self.observed = capability;
                            if self.ensure_capabilities && self.observed.is_empty() {
                                self.state = State::Capability(ImapCapabilityGet::new());
                                continue;
                            }
                            return ImapCoroutineState::Complete(Ok(mem::take(&mut self.observed)));
                        }
                        Err(err) => return ImapCoroutineState::Complete(Err(err)),
                    }
                }
                State::Capability(coroutine) => match coroutine.resume(fragmentizer, arg.take()) {
                    ImapCoroutineState::Yielded(y) => return ImapCoroutineState::Yielded(y),
                    ImapCoroutineState::Complete(Ok(capability)) => {
                        return ImapCoroutineState::Complete(Ok(capability));
                    }
                    ImapCoroutineState::Complete(Err(err)) => {
                        return ImapCoroutineState::Complete(Err(err.into()));
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
) -> Result<Vec<Capability<'static>>, ImapAuthPlainError> {
    let Some(Tagged { body, .. }) = tagged else {
        return Err(ImapAuthPlainError::MissingTagged);
    };

    let code = match body.kind {
        StatusKind::Ok => body.code,
        StatusKind::No => return Err(ImapAuthPlainError::No(body.text.to_string())),
        StatusKind::Bad => return Err(ImapAuthPlainError::Bad(body.text.to_string())),
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
