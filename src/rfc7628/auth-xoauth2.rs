//! I/O-free coroutine to authenticate an IMAP mailbox via XOAUTH2.

use core::mem;

use alloc::{borrow::ToOwned, string::String, string::ToString, vec::Vec};

use imap_codec::{
    AuthenticateDataCodec, CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        auth::{AuthMechanism, AuthenticateData},
        command::{Command, CommandBody},
        core::{IString, NString, TagGenerator},
        response::{
            Capability, Code, CommandContinuationRequest, Data, StatusBody, StatusKind, Tagged,
        },
        secret::Secret,
    },
};
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;

use crate::coroutine::*;
use crate::{rfc2971::id::*, rfc3501::capability::*, send::*};

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum ImapAuthXOAuth2Error {
    #[error("Parse IMAP AUTHENTICATE NO error: {0}")]
    No(String),
    #[error("Parse IMAP AUTHENTICATE NO error: {info} ({err})")]
    NoWithError { info: String, err: String },
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
    #[error("Parse IMAP AUTHENTICATE response: expected continuation request")]
    ExpectedContinuationRequest,
    #[error("Parse IMAP AUTHENTICATE XOAUTH2 error: expected NO got {kind:?}: {info}")]
    UnexpectedStatus { kind: StatusKind, info: String },

    #[error("Parse IMAP AUTHENTICATE XOAUTH2 error: expected continuation request got OK")]
    UnexpectedOk,

    #[error(transparent)]
    Capability(#[from] ImapCapabilityGetError),

    #[error(transparent)]
    ServerId(#[from] ImapServerIdError),
}

pub struct ImapAuthXOAuth2Params {
    username: String,
    token: Secret<String>,
    ir: bool,
}

impl ImapAuthXOAuth2Params {
    pub fn new(username: impl ToString, token: SecretString, ir: bool) -> Self {
        Self {
            username: username.to_string(),
            token: token.expose_secret().to_string().into(),
            ir,
        }
    }
}

enum State {
    Send(SendImapCommand<CommandCodec>),
    Continue(SendImapCommand<AuthenticateDataCodec>),
    AcknowledgeError(SendImapCommand<AuthenticateDataCodec>),
    Capability(ImapCapabilityGet),
    Id(ImapServerId),
}

/// I/O-free coroutine to authenticate an IMAP mailbox via XOAUTH2.
pub struct ImapAuthXOAuth2 {
    state: State,
    payload: String,
    ir: bool,
    observed: Vec<Capability<'static>>,
    ensure_capabilities: bool,
    error: Option<String>,
    auto_id: Option<Vec<(IString<'static>, NString<'static>)>>,
}

impl ImapAuthXOAuth2 {
    /// Creates a new coroutine. When `auto_id` is [`Some`], runs an
    /// extra `ID` round-trip (RFC 2971) after authentication; an
    /// empty vec maps to `ID NIL`.
    pub fn new(
        params: ImapAuthXOAuth2Params,
        ensure_capabilities: bool,
        auto_id: Option<Vec<(IString<'static>, NString<'static>)>>,
    ) -> Self {
        let username = &params.username;
        let token = params.token.declassify();
        let payload = format!("user={username}\x01auth=Bearer {token}\x01\x01");

        let initial_response = if params.ir {
            Some(Secret::new(payload.as_bytes().to_owned().into()))
        } else {
            None
        };

        let xoauth = CommandBody::Authenticate {
            mechanism: AuthMechanism::XOAuth2,
            initial_response,
        };

        let mut tag = TagGenerator::new();
        // SAFETY: tag is always valid
        let command = Command::new(tag.generate(), xoauth).unwrap();
        let send = SendImapCommand::new(CommandCodec::new(), command);

        Self {
            state: State::Send(send),
            payload,
            ir: params.ir,
            observed: Vec::new(),
            ensure_capabilities,
            error: None,
            auto_id,
        }
    }

    fn start_auto_id(&mut self) -> Option<State> {
        let params = self.auto_id.take()?;
        let wire = (!params.is_empty()).then_some(params);
        Some(State::Id(ImapServerId::new(wire)))
    }
}

impl ImapCoroutine for ImapAuthXOAuth2 {
    type Yield = ImapYield;
    type Return = Result<Vec<Capability<'static>>, ImapAuthXOAuth2Error>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        mut arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        loop {
            match &mut self.state {
                State::Send(send) => {
                    let (bye, continuation_request, tagged) =
                        match send.resume(fragmentizer, arg.take()) {
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
                                ..
                            } => (bye, continuation_request, tagged),
                            SendImapCommandResult::Err(err) => {
                                return ImapCoroutineState::Complete(Err(err.into()));
                            }
                        };

                    if let Some(bye) = bye {
                        return ImapCoroutineState::Complete(Err(ImapAuthXOAuth2Error::Bye(
                            bye.text.to_string(),
                        )));
                    }

                    if let Some(cr) = continuation_request {
                        if self.ir {
                            self.error.replace(match cr {
                                CommandContinuationRequest::Basic(err) => err.text().to_string(),
                                CommandContinuationRequest::Base64(err) => {
                                    String::from_utf8_lossy(err.as_ref()).to_string()
                                }
                            });

                            let auth = AuthenticateData::r#continue(vec![]);
                            let codec = AuthenticateDataCodec::new();
                            self.state = State::AcknowledgeError(SendImapCommand::new(codec, auth));
                        } else {
                            let payload = mem::take(&mut self.payload).into_bytes();
                            let auth = AuthenticateData::r#continue(payload);
                            let codec = AuthenticateDataCodec::new();
                            self.state = State::Continue(SendImapCommand::new(codec, auth));
                        }

                        continue;
                    }

                    if let Some(Tagged { body, .. }) = tagged {
                        let err = match body.kind {
                            StatusKind::Ok => ImapAuthXOAuth2Error::UnexpectedOk,
                            StatusKind::No => ImapAuthXOAuth2Error::No(body.text.to_string()),
                            StatusKind::Bad => ImapAuthXOAuth2Error::Bad(body.text.to_string()),
                        };

                        return ImapCoroutineState::Complete(Err(err));
                    }

                    if !self.ir {
                        return ImapCoroutineState::Complete(Err(
                            ImapAuthXOAuth2Error::ExpectedContinuationRequest,
                        ));
                    }

                    unreachable!();
                }
                State::Continue(send) => {
                    let (bye, continuation_request, tagged, data, untagged) =
                        match send.resume(fragmentizer, arg.take()) {
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
                        return ImapCoroutineState::Complete(Err(ImapAuthXOAuth2Error::Bye(
                            bye.text.to_string(),
                        )));
                    }

                    if let Some(cr) = continuation_request {
                        self.error.replace(match cr {
                            CommandContinuationRequest::Basic(err) => err.text().to_string(),
                            CommandContinuationRequest::Base64(err) => {
                                String::from_utf8_lossy(err.as_ref()).to_string()
                            }
                        });

                        let auth = AuthenticateData::r#continue(vec![]);
                        let codec = AuthenticateDataCodec::new();
                        self.state = State::AcknowledgeError(SendImapCommand::new(codec, auth));
                        continue;
                    }

                    let Some(Tagged { body, .. }) = tagged else {
                        return ImapCoroutineState::Complete(Err(
                            ImapAuthXOAuth2Error::MissingTagged,
                        ));
                    };

                    let code = match body.kind {
                        StatusKind::Ok => body.code,
                        StatusKind::No => {
                            return ImapCoroutineState::Complete(Err(ImapAuthXOAuth2Error::No(
                                body.text.to_string(),
                            )));
                        }
                        StatusKind::Bad => {
                            return ImapCoroutineState::Complete(Err(ImapAuthXOAuth2Error::Bad(
                                body.text.to_string(),
                            )));
                        }
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
                State::AcknowledgeError(send) => {
                    let (bye, tagged) = match send.resume(fragmentizer, arg.take()) {
                        SendImapCommandResult::WantsRead => {
                            return ImapCoroutineState::Yielded(ImapYield::WantsRead);
                        }
                        SendImapCommandResult::WantsWrite(bytes) => {
                            return ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes));
                        }
                        SendImapCommandResult::Ok { bye, tagged, .. } => (bye, tagged),
                        SendImapCommandResult::Err(err) => {
                            return ImapCoroutineState::Complete(Err(err.into()));
                        }
                    };

                    if let Some(bye) = bye {
                        return ImapCoroutineState::Complete(Err(ImapAuthXOAuth2Error::Bye(
                            bye.text.to_string(),
                        )));
                    }

                    let Some(Tagged { body, .. }) = tagged else {
                        return ImapCoroutineState::Complete(Err(
                            ImapAuthXOAuth2Error::MissingTagged,
                        ));
                    };

                    let StatusKind::No = body.kind else {
                        return ImapCoroutineState::Complete(Err(
                            ImapAuthXOAuth2Error::UnexpectedStatus {
                                kind: body.kind,
                                info: body.text.to_string(),
                            },
                        ));
                    };

                    let info = body.text.to_string();
                    let err = match self.error.take() {
                        Some(err) => ImapAuthXOAuth2Error::NoWithError { info, err },
                        None => ImapAuthXOAuth2Error::No(info),
                    };

                    return ImapCoroutineState::Complete(Err(err));
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
