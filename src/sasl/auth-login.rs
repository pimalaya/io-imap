//! I/O-free coroutine to authenticate an IMAP mailbox via the SASL
//! `LOGIN` mechanism.
//!
//! Distinct from the RFC 3501 `LOGIN` command: the SASL `LOGIN`
//! mechanism is a legacy two-prompt scheme invoked via
//! `AUTHENTICATE LOGIN`; the server requests the username and the
//! password in turn through base64-encoded continuation challenges.
//! It was never RFC-standardized but is widely implemented.

use core::mem;

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    AuthenticateDataCodec, CommandCodec,
    imap_types::{
        auth::{AuthMechanism, AuthenticateData},
        command::{Command, CommandBody},
        response::{Code, Data, StatusBody, StatusKind, Tagged},
    },
};
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;

use crate::{context::ImapContext, rfc3501::capability::*, send::*};

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

/// Output emitted when the coroutine terminates its progression.
pub enum ImapAuthLoginResult {
    Ok {
        context: ImapContext,
    },
    WantsRead,
    WantsWrite(Vec<u8>),
    Err {
        context: ImapContext,
        err: ImapAuthLoginError,
    },
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
    ensure_capabilities: bool,
}

impl ImapAuthLogin {
    /// Creates a new coroutine. When `ensure_capabilities` is true and the
    /// server did not piggyback a capability list on the AUTHENTICATE tagged
    /// response, the coroutine drives an extra `CAPABILITY` round-trip
    /// before completing.
    pub fn new(
        mut context: ImapContext,
        params: ImapAuthLoginParams,
        ensure_capabilities: bool,
    ) -> Self {
        let body = CommandBody::Authenticate {
            mechanism: AuthMechanism::Login,
            initial_response: None,
        };

        // SAFETY: tag is always valid
        let command = Command::new(context.generate_tag(), body).unwrap();
        let send = SendImapCommand::new(context, CommandCodec::new(), command);

        Self {
            state: State::Send(send),
            username: params.username,
            password: params.password,
            ensure_capabilities,
        }
    }

    /// Advances the coroutine.
    pub fn resume(&mut self, mut arg: Option<&[u8]>) -> ImapAuthLoginResult {
        loop {
            match &mut self.state {
                State::Send(coroutine) => {
                    let (context, bye, continuation_request) = match coroutine.resume(arg.take()) {
                        SendImapCommandResult::WantsRead => {
                            break ImapAuthLoginResult::WantsRead;
                        }
                        SendImapCommandResult::WantsWrite(bytes) => {
                            break ImapAuthLoginResult::WantsWrite(bytes);
                        }
                        SendImapCommandResult::Ok {
                            context,
                            bye,
                            continuation_request,
                            ..
                        } => (context, bye, continuation_request),
                        SendImapCommandResult::Err { context, err } => {
                            break ImapAuthLoginResult::Err {
                                context,
                                err: err.into(),
                            };
                        }
                    };

                    if let Some(bye) = bye {
                        let err = ImapAuthLoginError::Bye(bye.text.to_string());
                        return ImapAuthLoginResult::Err { context, err };
                    }

                    if continuation_request.is_none() {
                        let err = ImapAuthLoginError::MissingContinuationRequest;
                        return ImapAuthLoginResult::Err { context, err };
                    }

                    let username = mem::take(&mut self.username).into_bytes();
                    let auth = AuthenticateData::r#continue(username);
                    let codec = AuthenticateDataCodec::new();
                    self.state =
                        State::ContinueUsername(SendImapCommand::new(context, codec, auth));
                }
                State::ContinueUsername(coroutine) => {
                    let (context, bye, continuation_request) = match coroutine.resume(arg.take()) {
                        SendImapCommandResult::WantsRead => {
                            break ImapAuthLoginResult::WantsRead;
                        }
                        SendImapCommandResult::WantsWrite(bytes) => {
                            break ImapAuthLoginResult::WantsWrite(bytes);
                        }
                        SendImapCommandResult::Ok {
                            context,
                            bye,
                            continuation_request,
                            ..
                        } => (context, bye, continuation_request),
                        SendImapCommandResult::Err { context, err } => {
                            break ImapAuthLoginResult::Err {
                                context,
                                err: err.into(),
                            };
                        }
                    };

                    if let Some(bye) = bye {
                        let err = ImapAuthLoginError::Bye(bye.text.to_string());
                        return ImapAuthLoginResult::Err { context, err };
                    }

                    if continuation_request.is_none() {
                        let err = ImapAuthLoginError::MissingContinuationRequest;
                        return ImapAuthLoginResult::Err { context, err };
                    }

                    let password = mem::take(&mut self.password).into_bytes();
                    let auth = AuthenticateData::r#continue(password);
                    let codec = AuthenticateDataCodec::new();
                    self.state =
                        State::ContinuePassword(SendImapCommand::new(context, codec, auth));
                }
                State::ContinuePassword(coroutine) => {
                    let (context, bye, continuation_request, tagged, data, untagged) =
                        match coroutine.resume(arg.take()) {
                            SendImapCommandResult::WantsRead => {
                                break ImapAuthLoginResult::WantsRead;
                            }
                            SendImapCommandResult::WantsWrite(bytes) => {
                                break ImapAuthLoginResult::WantsWrite(bytes);
                            }
                            SendImapCommandResult::Ok {
                                context,
                                bye,
                                continuation_request,
                                tagged,
                                data,
                                untagged,
                                ..
                            } => (context, bye, continuation_request, tagged, data, untagged),
                            SendImapCommandResult::Err { context, err } => {
                                break ImapAuthLoginResult::Err {
                                    context,
                                    err: err.into(),
                                };
                            }
                        };

                    if let Some(bye) = bye {
                        let err = ImapAuthLoginError::Bye(bye.text.to_string());
                        return ImapAuthLoginResult::Err { context, err };
                    }

                    if continuation_request.is_some() {
                        let err = ImapAuthLoginError::UnexpectedContinuationRequest;
                        return ImapAuthLoginResult::Err { context, err };
                    }

                    match finish(context, tagged, data, untagged) {
                        Ok(context) => {
                            if self.ensure_capabilities && context.capability.is_empty() {
                                self.state = State::Capability(ImapCapabilityGet::new(context));
                                continue;
                            }
                            return ImapAuthLoginResult::Ok { context };
                        }
                        Err((context, err)) => {
                            return ImapAuthLoginResult::Err { context, err };
                        }
                    }
                }
                State::Capability(coroutine) => match coroutine.resume(arg.take()) {
                    ImapCapabilityGetResult::WantsRead => {
                        break ImapAuthLoginResult::WantsRead;
                    }
                    ImapCapabilityGetResult::WantsWrite(bytes) => {
                        break ImapAuthLoginResult::WantsWrite(bytes);
                    }
                    ImapCapabilityGetResult::Ok { context } => {
                        break ImapAuthLoginResult::Ok { context };
                    }
                    ImapCapabilityGetResult::Err { context, err } => {
                        break ImapAuthLoginResult::Err {
                            context,
                            err: err.into(),
                        };
                    }
                },
            }
        }
    }
}

fn finish(
    mut context: ImapContext,
    tagged: Option<Tagged<'static>>,
    data: Vec<Data<'static>>,
    untagged: Vec<StatusBody<'static>>,
) -> Result<ImapContext, (ImapContext, ImapAuthLoginError)> {
    let Some(Tagged { body, .. }) = tagged else {
        let err = ImapAuthLoginError::MissingTagged;
        return Err((context, err));
    };

    let code = match body.kind {
        StatusKind::Ok => body.code,
        StatusKind::No => {
            let err = ImapAuthLoginError::No(body.text.to_string());
            return Err((context, err));
        }
        StatusKind::Bad => {
            let err = ImapAuthLoginError::Bad(body.text.to_string());
            return Err((context, err));
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
        context.capability = capability.into_iter().collect();
    }

    context.authenticated = true;

    Ok(context)
}
