//! I/O-free coroutine to authenticate via OAUTHBEARER (RFC 7628).

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
use thiserror::Error;

use crate::{context::ImapContext, rfc3501::capability::*, send::*};

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
}

/// Output emitted when the coroutine terminates its progression.
pub enum ImapAuthOAuthBearerResult {
    Ok {
        context: ImapContext,
    },
    WantsRead,
    WantsWrite(Vec<u8>),
    Err {
        context: ImapContext,
        err: ImapAuthOAuthBearerError,
    },
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
        token: Secret<String>,
        ir: bool,
    ) -> Self {
        Self {
            username: username.to_string(),
            host: host.to_string(),
            port,
            token,
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

/// I/O-free coroutine to authenticate via OAUTHBEARER (RFC 7628).
pub struct ImapAuthOAuthBearer {
    state: State,
    payload: String,
    ir: bool,
    ensure_capabilities: bool,
    error: Option<String>,
}

impl ImapAuthOAuthBearer {
    /// Creates a new coroutine. When `ensure_capabilities` is true and the
    /// server did not piggyback a capability list on the AUTHENTICATE tagged
    /// response, the coroutine drives an extra `CAPABILITY` round-trip
    /// before completing.
    pub fn new(
        mut context: ImapContext,
        params: ImapAuthOAuthBearerParams,
        ensure_capabilities: bool,
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

        // SAFETY: tag is always valid
        let command = Command::new(context.generate_tag(), body).unwrap();
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
    pub fn resume(&mut self, mut arg: Option<&[u8]>) -> ImapAuthOAuthBearerResult {
        loop {
            match &mut self.state {
                State::Send(send) => {
                    let (context, bye, continuation_request, tagged) = match send.resume(arg.take())
                    {
                        SendImapCommandResult::WantsRead => {
                            break ImapAuthOAuthBearerResult::WantsRead;
                        }
                        SendImapCommandResult::WantsWrite(bytes) => {
                            break ImapAuthOAuthBearerResult::WantsWrite(bytes);
                        }
                        SendImapCommandResult::Ok {
                            context,
                            bye,
                            continuation_request,
                            tagged,
                            ..
                        } => (context, bye, continuation_request, tagged),
                        SendImapCommandResult::Err { context, err } => {
                            break ImapAuthOAuthBearerResult::Err {
                                context,
                                err: err.into(),
                            };
                        }
                    };

                    if let Some(bye) = bye {
                        let err = ImapAuthOAuthBearerError::Bye(bye.text.to_string());
                        return ImapAuthOAuthBearerResult::Err { context, err };
                    }

                    if let Some(cr) = continuation_request {
                        if self.ir {
                            // Server rejected our IR and sent an error in
                            // the continuation request. Acknowledge with
                            // a single SOH byte (RFC 7628 §3.2.3).
                            self.error.replace(match cr {
                                CommandContinuationRequest::Basic(err) => err.text().to_string(),
                                CommandContinuationRequest::Base64(err) => {
                                    String::from_utf8_lossy(err.as_ref()).to_string()
                                }
                            });

                            let auth = AuthenticateData::r#continue(vec![0x01]);
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
                            StatusKind::Ok => ImapAuthOAuthBearerError::UnexpectedOk,
                            StatusKind::No => ImapAuthOAuthBearerError::No(body.text.to_string()),
                            StatusKind::Bad => ImapAuthOAuthBearerError::Bad(body.text.to_string()),
                        };

                        return ImapAuthOAuthBearerResult::Err { context, err };
                    }

                    if !self.ir {
                        let err = ImapAuthOAuthBearerError::ExpectedContinuationRequest;
                        return ImapAuthOAuthBearerResult::Err { context, err };
                    }

                    unreachable!();
                }
                State::Continue(send) => {
                    let (mut context, bye, continuation_request, tagged, data, untagged) =
                        match send.resume(arg.take()) {
                            SendImapCommandResult::WantsRead => {
                                break ImapAuthOAuthBearerResult::WantsRead;
                            }
                            SendImapCommandResult::WantsWrite(bytes) => {
                                break ImapAuthOAuthBearerResult::WantsWrite(bytes);
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
                                break ImapAuthOAuthBearerResult::Err {
                                    context,
                                    err: err.into(),
                                };
                            }
                        };

                    if let Some(bye) = bye {
                        let err = ImapAuthOAuthBearerError::Bye(bye.text.to_string());
                        return ImapAuthOAuthBearerResult::Err { context, err };
                    }

                    if let Some(cr) = continuation_request {
                        // Server sent an error in continuation after
                        // receiving our payload. Acknowledge with SOH.
                        self.error.replace(match cr {
                            CommandContinuationRequest::Basic(err) => err.text().to_string(),
                            CommandContinuationRequest::Base64(err) => {
                                String::from_utf8_lossy(err.as_ref()).to_string()
                            }
                        });

                        let auth = AuthenticateData::r#continue(vec![0x01]);
                        let codec = AuthenticateDataCodec::new();
                        self.state =
                            State::AcknowledgeError(SendImapCommand::new(context, codec, auth));
                        continue;
                    }

                    let Some(Tagged { body, .. }) = tagged else {
                        let err = ImapAuthOAuthBearerError::MissingTagged;
                        return ImapAuthOAuthBearerResult::Err { context, err };
                    };

                    let code = match body.kind {
                        StatusKind::Ok => body.code,
                        StatusKind::No => {
                            let err = ImapAuthOAuthBearerError::No(body.text.to_string());
                            return ImapAuthOAuthBearerResult::Err { context, err };
                        }
                        StatusKind::Bad => {
                            let err = ImapAuthOAuthBearerError::Bad(body.text.to_string());
                            return ImapAuthOAuthBearerResult::Err { context, err };
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

                    return ImapAuthOAuthBearerResult::Ok { context };
                }
                State::AcknowledgeError(send) => {
                    let (context, bye, tagged) = match send.resume(arg.take()) {
                        SendImapCommandResult::WantsRead => {
                            break ImapAuthOAuthBearerResult::WantsRead;
                        }
                        SendImapCommandResult::WantsWrite(bytes) => {
                            break ImapAuthOAuthBearerResult::WantsWrite(bytes);
                        }
                        SendImapCommandResult::Ok {
                            context,
                            bye,
                            tagged,
                            ..
                        } => (context, bye, tagged),
                        SendImapCommandResult::Err { context, err } => {
                            break ImapAuthOAuthBearerResult::Err {
                                context,
                                err: err.into(),
                            };
                        }
                    };

                    if let Some(bye) = bye {
                        let err = ImapAuthOAuthBearerError::Bye(bye.text.to_string());
                        return ImapAuthOAuthBearerResult::Err { context, err };
                    }

                    let Some(Tagged { body, .. }) = tagged else {
                        let err = ImapAuthOAuthBearerError::MissingTagged;
                        return ImapAuthOAuthBearerResult::Err { context, err };
                    };

                    let StatusKind::No = body.kind else {
                        let err = ImapAuthOAuthBearerError::UnexpectedStatus {
                            kind: body.kind,
                            info: body.text.to_string(),
                        };
                        return ImapAuthOAuthBearerResult::Err { context, err };
                    };

                    let info = body.text.to_string();
                    let err = match self.error.take() {
                        Some(err) => ImapAuthOAuthBearerError::NoWithError { info, err },
                        None => ImapAuthOAuthBearerError::No(info),
                    };

                    return ImapAuthOAuthBearerResult::Err { context, err };
                }
                State::Capability(coroutine) => match coroutine.resume(arg.take()) {
                    ImapCapabilityGetResult::WantsRead => {
                        break ImapAuthOAuthBearerResult::WantsRead;
                    }
                    ImapCapabilityGetResult::WantsWrite(bytes) => {
                        break ImapAuthOAuthBearerResult::WantsWrite(bytes);
                    }
                    ImapCapabilityGetResult::Ok { context } => {
                        break ImapAuthOAuthBearerResult::Ok { context };
                    }
                    ImapCapabilityGetResult::Err { context, err } => {
                        break ImapAuthOAuthBearerResult::Err {
                            context,
                            err: err.into(),
                        };
                    }
                },
            }
        }
    }
}
