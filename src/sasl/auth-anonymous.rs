//! I/O-free coroutine to authenticate an IMAP mailbox via ANONYMOUS
//! (RFC 4505).

use core::mem;

use alloc::{borrow::ToOwned, string::String, string::ToString, vec::Vec};

use imap_codec::{
    AuthenticateDataCodec, CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        auth::{AuthMechanism, AuthenticateData},
        command::{Command, CommandBody},
        core::{IString, NString, TagGenerator},
        response::{Capability, Code, Data, StatusBody, StatusKind, Tagged},
        secret::Secret,
    },
};
use thiserror::Error;

use crate::coroutine::*;
use crate::{rfc2971::id::*, rfc3501::capability::*, send::*};

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum ImapAuthAnonymousError {
    #[error("Parse IMAP AUTHENTICATE ANONYMOUS NO error: {0}")]
    No(String),
    #[error("Parse IMAP AUTHENTICATE ANONYMOUS BAD error: {0}")]
    Bad(String),
    #[error("Parse IMAP AUTHENTICATE ANONYMOUS BYE error: {0}")]
    Bye(String),

    #[error("No IMAP AUTHENTICATE tagged response returned by the server")]
    MissingTagged,

    #[error("Send IMAP AUTHENTICATE command error")]
    Send(#[from] SendImapCommandError),

    #[error("Parse IMAP AUTHENTICATE ANONYMOUS response: unexpected continuation request")]
    UnexpectedContinuationRequest,
    #[error("Parse IMAP AUTHENTICATE ANONYMOUS response: missing continuation request")]
    MissingContinuationRequest,

    #[error(transparent)]
    Capability(#[from] ImapCapabilityGetError),

    #[error(transparent)]
    ServerId(#[from] ImapServerIdError),
}

pub struct ImapAuthAnonymousParams {
    pub message: Option<String>,
    pub ir: bool,
}

impl ImapAuthAnonymousParams {
    pub fn new(message: impl ToString, ir: bool) -> Self {
        Self {
            message: Some(message.to_string()),
            ir,
        }
    }
}

enum State {
    Send(SendImapCommand<CommandCodec>),
    Continue(SendImapCommand<AuthenticateDataCodec>),
    Capability(ImapCapabilityGet),
    Id(ImapServerId),
}

/// I/O-free coroutine to authenticate an IMAP mailbox via ANONYMOUS
/// (RFC 4505).
pub struct ImapAuthAnonymous {
    state: State,
    message: Option<String>,
    ir: bool,
    observed: Vec<Capability<'static>>,
    ensure_capabilities: bool,
    auto_id: Option<Vec<(IString<'static>, NString<'static>)>>,
}

impl ImapAuthAnonymous {
    /// Creates a new coroutine. When `auto_id` is [`Some`], runs an
    /// extra `ID` round-trip (RFC 2971) after authentication; an
    /// empty vec maps to `ID NIL`.
    pub fn new(
        params: ImapAuthAnonymousParams,
        ensure_capabilities: bool,
        auto_id: Option<Vec<(IString<'static>, NString<'static>)>>,
    ) -> Self {
        let msg = params.message.as_ref().unwrap().as_bytes().to_owned();

        let initial_response = if params.ir {
            Some(Secret::new(msg.into()))
        } else {
            None
        };

        let anonymous = CommandBody::Authenticate {
            // SAFETY: ANONYMOUS is a valid mechanism name
            mechanism: AuthMechanism::try_from("ANONYMOUS").unwrap(),
            initial_response,
        };

        let mut tag = TagGenerator::new();
        // SAFETY: tag is always valid
        let command = Command::new(tag.generate(), anonymous).unwrap();
        let send = SendImapCommand::new(CommandCodec::new(), command);

        Self {
            state: State::Send(send),
            message: params.message,
            ir: params.ir,
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

impl ImapCoroutine for ImapAuthAnonymous {
    type Yield = ImapYield;
    type Return = Result<Vec<Capability<'static>>, ImapAuthAnonymousError>;

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
                        return ImapCoroutineState::Complete(Err(ImapAuthAnonymousError::Bye(
                            bye.text.to_string(),
                        )));
                    }

                    if continuation_request.is_some() {
                        if self.ir {
                            return ImapCoroutineState::Complete(Err(
                                ImapAuthAnonymousError::UnexpectedContinuationRequest,
                            ));
                        }

                        let message = self.message.take().unwrap().into_bytes();
                        let auth = AuthenticateData::r#continue(message);
                        let codec = AuthenticateDataCodec::new();
                        self.state = State::Continue(SendImapCommand::new(codec, auth));
                        continue;
                    }

                    if !self.ir {
                        return ImapCoroutineState::Complete(Err(
                            ImapAuthAnonymousError::MissingContinuationRequest,
                        ));
                    }

                    match finish(tagged, data, untagged) {
                        Ok(capability) => {
                            self.observed = capability;
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
                        return ImapCoroutineState::Complete(Err(ImapAuthAnonymousError::Bye(
                            bye.text.to_string(),
                        )));
                    }

                    if continuation_request.is_some() {
                        return ImapCoroutineState::Complete(Err(
                            ImapAuthAnonymousError::UnexpectedContinuationRequest,
                        ));
                    }

                    match finish(tagged, data, untagged) {
                        Ok(capability) => {
                            self.observed = capability;
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
                        Err(err) => return ImapCoroutineState::Complete(Err(err)),
                    }
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

fn finish(
    tagged: Option<Tagged<'static>>,
    data: Vec<Data<'static>>,
    untagged: Vec<StatusBody<'static>>,
) -> Result<Vec<Capability<'static>>, ImapAuthAnonymousError> {
    let Some(Tagged { body, .. }) = tagged else {
        return Err(ImapAuthAnonymousError::MissingTagged);
    };

    let code = match body.kind {
        StatusKind::Ok => body.code,
        StatusKind::No => return Err(ImapAuthAnonymousError::No(body.text.to_string())),
        StatusKind::Bad => return Err(ImapAuthAnonymousError::Bad(body.text.to_string())),
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
