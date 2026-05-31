//! I/O-free coroutine to authenticate via OAUTHBEARER (RFC 7628).

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
pub enum ImapAuthOAuthBearerError {
    #[error("IMAP AUTHENTICATE OAUTHBEARER NO error: {0}")]
    No(String),
    #[error("IMAP AUTHENTICATE OAUTHBEARER NO error: {info} ({err})")]
    NoWithError { info: String, err: String },
    #[error("IMAP AUTHENTICATE OAUTHBEARER BAD error: {0}")]
    Bad(String),
    #[error("IMAP AUTHENTICATE OAUTHBEARER BYE error: {0}")]
    Bye(String),

    #[error("No IMAP AUTHENTICATE tagged response returned by the server")]
    MissingTagged,

    #[error("Send IMAP AUTHENTICATE command error")]
    Send(#[from] SendImapCommandError),

    #[error("IMAP AUTHENTICATE OAUTHBEARER: unexpected continuation request")]
    UnexpectedContinuationRequest,
    #[error("IMAP AUTHENTICATE OAUTHBEARER: expected continuation request")]
    ExpectedContinuationRequest,
    #[error("IMAP AUTHENTICATE OAUTHBEARER: expected NO got {kind:?}: {info}")]
    UnexpectedStatus { kind: StatusKind, info: String },

    #[error("IMAP AUTHENTICATE OAUTHBEARER: expected continuation request got OK")]
    UnexpectedOk,

    #[error(transparent)]
    Capability(#[from] ImapCapabilityGetError),

    #[error(transparent)]
    ServerId(#[from] ImapServerIdError),
}

pub struct ImapAuthOAuthBearerParams {
    username: String,
    host: String,
    port: u16,
    token: Secret<String>,
    ir: bool,
}

impl ImapAuthOAuthBearerParams {
    pub fn new(
        username: impl ToString,
        host: impl ToString,
        port: u16,
        token: SecretString,
        ir: bool,
    ) -> Self {
        Self {
            username: username.to_string(),
            host: host.to_string(),
            port,
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

/// I/O-free coroutine to authenticate via OAUTHBEARER (RFC 7628).
pub struct ImapAuthOAuthBearer {
    state: State,
    payload: String,
    ir: bool,
    observed: Vec<Capability<'static>>,
    ensure_capabilities: bool,
    error: Option<String>,
    auto_id: Option<Vec<(IString<'static>, NString<'static>)>>,
}

impl ImapAuthOAuthBearer {
    /// Creates a new coroutine. When `auto_id` is [`Some`], runs an
    /// extra `ID` round-trip (RFC 2971) after authentication; an
    /// empty vec maps to `ID NIL`.
    pub fn new(
        params: ImapAuthOAuthBearerParams,
        ensure_capabilities: bool,
        auto_id: Option<Vec<(IString<'static>, NString<'static>)>>,
    ) -> Self {
        let username = &params.username;
        let host = &params.host;
        let port = params.port;
        let token = params.token.declassify();
        let payload =
            format!("n,a={username},\x01host={host}\x01port={port}\x01auth=Bearer {token}\x01\x01");

        let initial_response = if params.ir {
            Some(Secret::new(payload.as_bytes().to_owned().into()))
        } else {
            None
        };

        let body = CommandBody::Authenticate {
            mechanism: AuthMechanism::OAuthBearer,
            initial_response,
        };

        let mut tag = TagGenerator::new();
        // SAFETY: tag is always valid
        let command = Command::new(tag.generate(), body).unwrap();
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

impl ImapCoroutine for ImapAuthOAuthBearer {
    type Yield = ImapYield;
    type Return = Result<Vec<Capability<'static>>, ImapAuthOAuthBearerError>;

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
                        return ImapCoroutineState::Complete(Err(ImapAuthOAuthBearerError::Bye(
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

                            let auth = AuthenticateData::r#continue(vec![0x01]);
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
                            StatusKind::Ok => ImapAuthOAuthBearerError::UnexpectedOk,
                            StatusKind::No => ImapAuthOAuthBearerError::No(body.text.to_string()),
                            StatusKind::Bad => ImapAuthOAuthBearerError::Bad(body.text.to_string()),
                        };

                        return ImapCoroutineState::Complete(Err(err));
                    }

                    if !self.ir {
                        return ImapCoroutineState::Complete(Err(
                            ImapAuthOAuthBearerError::ExpectedContinuationRequest,
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
                        return ImapCoroutineState::Complete(Err(ImapAuthOAuthBearerError::Bye(
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

                        let auth = AuthenticateData::r#continue(vec![0x01]);
                        let codec = AuthenticateDataCodec::new();
                        self.state = State::AcknowledgeError(SendImapCommand::new(codec, auth));
                        continue;
                    }

                    let Some(Tagged { body, .. }) = tagged else {
                        return ImapCoroutineState::Complete(Err(
                            ImapAuthOAuthBearerError::MissingTagged,
                        ));
                    };

                    let code = match body.kind {
                        StatusKind::Ok => body.code,
                        StatusKind::No => {
                            return ImapCoroutineState::Complete(Err(
                                ImapAuthOAuthBearerError::No(body.text.to_string()),
                            ));
                        }
                        StatusKind::Bad => {
                            return ImapCoroutineState::Complete(Err(
                                ImapAuthOAuthBearerError::Bad(body.text.to_string()),
                            ));
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
                        return ImapCoroutineState::Complete(Err(ImapAuthOAuthBearerError::Bye(
                            bye.text.to_string(),
                        )));
                    }

                    let Some(Tagged { body, .. }) = tagged else {
                        return ImapCoroutineState::Complete(Err(
                            ImapAuthOAuthBearerError::MissingTagged,
                        ));
                    };

                    let StatusKind::No = body.kind else {
                        return ImapCoroutineState::Complete(Err(
                            ImapAuthOAuthBearerError::UnexpectedStatus {
                                kind: body.kind,
                                info: body.text.to_string(),
                            },
                        ));
                    };

                    let info = body.text.to_string();
                    let err = match self.error.take() {
                        Some(err) => ImapAuthOAuthBearerError::NoWithError { info, err },
                        None => ImapAuthOAuthBearerError::No(info),
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
