//! I/O-free coroutine to authenticate an IMAP mailbox via XOAUTH2.

use core::mem;

use alloc::{borrow::ToOwned, string::String, string::ToString, vec::Vec};

use imap_codec::{
    AuthenticateDataCodec, CommandCodec,
    imap_types::{
        auth::{AuthMechanism, AuthenticateData},
        command::{Command, CommandBody},
        response::{Code, CommandContinuationRequest, Data, StatusBody, StatusKind, Tagged},
        secret::Secret,
    },
};
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;

use crate::{context::ImapContext, rfc3501::capability::*, send::*};

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
}

/// Output emitted when the coroutine terminates its progression.
pub enum ImapAuthXOAuth2Result {
    Ok {
        context: ImapContext,
    },
    WantsRead,
    WantsWrite(Vec<u8>),
    Err {
        context: ImapContext,
        err: ImapAuthXOAuth2Error,
    },
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
}

/// I/O-free coroutine to authenticate an IMAP mailbox via XOAUTH2.
pub struct ImapAuthXOAuth2 {
    state: State,
    payload: String,
    ir: bool,
    ensure_capabilities: bool,
    error: Option<String>,
}

impl ImapAuthXOAuth2 {
    /// Creates a new coroutine. When `ensure_capabilities` is true and the
    /// server did not piggyback a capability list on the AUTHENTICATE tagged
    /// response, the coroutine drives an extra `CAPABILITY` round-trip
    /// before completing.
    pub fn new(
        mut context: ImapContext,
        params: ImapAuthXOAuth2Params,
        ensure_capabilities: bool,
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

        // SAFETY: tag is always valid
        let command = Command::new(context.generate_tag(), xoauth).unwrap();
        let send = SendImapCommand::new(context, CommandCodec::new(), command);

        Self {
            state: State::Send(send),
            payload,
            ir: params.ir,
            ensure_capabilities,
            error: None,
        }
    }

    /// Advances the coroutine.
    pub fn resume(&mut self, mut arg: Option<&[u8]>) -> ImapAuthXOAuth2Result {
        loop {
            match &mut self.state {
                State::Send(send) => {
                    let (context, bye, continuation_request, tagged) = match send.resume(arg.take())
                    {
                        SendImapCommandResult::WantsRead => {
                            break ImapAuthXOAuth2Result::WantsRead;
                        }
                        SendImapCommandResult::WantsWrite(bytes) => {
                            break ImapAuthXOAuth2Result::WantsWrite(bytes);
                        }
                        SendImapCommandResult::Ok {
                            context,
                            bye,
                            continuation_request,
                            tagged,
                            ..
                        } => (context, bye, continuation_request, tagged),
                        SendImapCommandResult::Err { context, err } => {
                            break ImapAuthXOAuth2Result::Err {
                                context,
                                err: err.into(),
                            };
                        }
                    };

                    if let Some(bye) = bye {
                        let err = ImapAuthXOAuth2Error::Bye(bye.text.to_string());
                        return ImapAuthXOAuth2Result::Err { context, err };
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
                            self.state =
                                State::AcknowledgeError(SendImapCommand::new(context, codec, auth));
                        } else {
                            let payload = mem::take(&mut self.payload).into_bytes();
                            let auth = AuthenticateData::r#continue(payload);
                            let codec = AuthenticateDataCodec::new();
                            self.state =
                                State::Continue(SendImapCommand::new(context, codec, auth));
                        }

                        continue;
                    }

                    if let Some(Tagged { body, .. }) = tagged {
                        let err = match body.kind {
                            StatusKind::Ok => ImapAuthXOAuth2Error::UnexpectedOk,
                            StatusKind::No => ImapAuthXOAuth2Error::No(body.text.to_string()),
                            StatusKind::Bad => ImapAuthXOAuth2Error::Bad(body.text.to_string()),
                        };

                        return ImapAuthXOAuth2Result::Err { context, err };
                    }

                    if !self.ir {
                        let err = ImapAuthXOAuth2Error::ExpectedContinuationRequest;
                        return ImapAuthXOAuth2Result::Err { context, err };
                    }

                    unreachable!();
                }
                State::Continue(send) => {
                    let (mut context, bye, continuation_request, tagged, data, untagged) =
                        match send.resume(arg.take()) {
                            SendImapCommandResult::WantsRead => {
                                break ImapAuthXOAuth2Result::WantsRead;
                            }
                            SendImapCommandResult::WantsWrite(bytes) => {
                                break ImapAuthXOAuth2Result::WantsWrite(bytes);
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
                                break ImapAuthXOAuth2Result::Err {
                                    context,
                                    err: err.into(),
                                };
                            }
                        };

                    if let Some(bye) = bye {
                        let err = ImapAuthXOAuth2Error::Bye(bye.text.to_string());
                        return ImapAuthXOAuth2Result::Err { context, err };
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
                        self.state =
                            State::AcknowledgeError(SendImapCommand::new(context, codec, auth));
                        continue;
                    }

                    let Some(Tagged { body, .. }) = tagged else {
                        let err = ImapAuthXOAuth2Error::MissingTagged;
                        return ImapAuthXOAuth2Result::Err { context, err };
                    };

                    let code = match body.kind {
                        StatusKind::Ok => body.code,
                        StatusKind::No => {
                            let err = ImapAuthXOAuth2Error::No(body.text.to_string());
                            return ImapAuthXOAuth2Result::Err { context, err };
                        }
                        StatusKind::Bad => {
                            let err = ImapAuthXOAuth2Error::Bad(body.text.to_string());
                            return ImapAuthXOAuth2Result::Err { context, err };
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

                    if self.ensure_capabilities && context.capability.is_empty() {
                        self.state = State::Capability(ImapCapabilityGet::new(context));
                        continue;
                    }

                    return ImapAuthXOAuth2Result::Ok { context };
                }
                State::AcknowledgeError(send) => {
                    let (context, bye, tagged) = match send.resume(arg.take()) {
                        SendImapCommandResult::WantsRead => {
                            break ImapAuthXOAuth2Result::WantsRead;
                        }
                        SendImapCommandResult::WantsWrite(bytes) => {
                            break ImapAuthXOAuth2Result::WantsWrite(bytes);
                        }
                        SendImapCommandResult::Ok {
                            context,
                            bye,
                            tagged,
                            ..
                        } => (context, bye, tagged),
                        SendImapCommandResult::Err { context, err } => {
                            break ImapAuthXOAuth2Result::Err {
                                context,
                                err: err.into(),
                            };
                        }
                    };

                    if let Some(bye) = bye {
                        let err = ImapAuthXOAuth2Error::Bye(bye.text.to_string());
                        return ImapAuthXOAuth2Result::Err { context, err };
                    }

                    let Some(Tagged { body, .. }) = tagged else {
                        let err = ImapAuthXOAuth2Error::MissingTagged;
                        return ImapAuthXOAuth2Result::Err { context, err };
                    };

                    let StatusKind::No = body.kind else {
                        let err = ImapAuthXOAuth2Error::UnexpectedStatus {
                            kind: body.kind,
                            info: body.text.to_string(),
                        };
                        return ImapAuthXOAuth2Result::Err { context, err };
                    };

                    let info = body.text.to_string();
                    let err = match self.error.take() {
                        Some(err) => ImapAuthXOAuth2Error::NoWithError { info, err },
                        None => ImapAuthXOAuth2Error::No(info),
                    };

                    return ImapAuthXOAuth2Result::Err { context, err };
                }
                State::Capability(coroutine) => match coroutine.resume(arg.take()) {
                    ImapCapabilityGetResult::WantsRead => {
                        break ImapAuthXOAuth2Result::WantsRead;
                    }
                    ImapCapabilityGetResult::WantsWrite(bytes) => {
                        break ImapAuthXOAuth2Result::WantsWrite(bytes);
                    }
                    ImapCapabilityGetResult::Ok { context } => {
                        break ImapAuthXOAuth2Result::Ok { context };
                    }
                    ImapCapabilityGetResult::Err { context, err } => {
                        break ImapAuthXOAuth2Result::Err {
                            context,
                            err: err.into(),
                        };
                    }
                },
            }
        }
    }
}
