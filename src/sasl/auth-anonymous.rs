//! I/O-free coroutine to authenticate an IMAP mailbox via ANONYMOUS
//! (RFC 4505).

use alloc::{borrow::ToOwned, string::String, string::ToString, vec::Vec};

use imap_codec::{
    AuthenticateDataCodec, CommandCodec,
    imap_types::{
        auth::{AuthMechanism, AuthenticateData},
        command::{Command, CommandBody},
        response::{Code, Data, StatusBody, StatusKind, Tagged},
        secret::Secret,
    },
};
use thiserror::Error;

use crate::{context::ImapContext, rfc3501::capability::*, send::*};

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
}

/// Output emitted when the coroutine terminates its progression.
pub enum ImapAuthAnonymousResult {
    Ok {
        context: ImapContext,
    },
    WantsRead,
    WantsWrite(Vec<u8>),
    Err {
        context: ImapContext,
        err: ImapAuthAnonymousError,
    },
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
}

/// I/O-free coroutine to authenticate an IMAP mailbox via ANONYMOUS
/// (RFC 4505).
pub struct ImapAuthAnonymous {
    state: State,
    message: Option<String>,
    ir: bool,
    ensure_capabilities: bool,
}

impl ImapAuthAnonymous {
    /// Creates a new coroutine. When `ensure_capabilities` is true and the
    /// server did not piggyback a capability list on the AUTHENTICATE tagged
    /// response, the coroutine drives an extra `CAPABILITY` round-trip
    /// before completing.
    pub fn new(
        mut context: ImapContext,
        params: ImapAuthAnonymousParams,
        ensure_capabilities: bool,
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

        // SAFETY: tag is always valid
        let command = Command::new(context.generate_tag(), anonymous).unwrap();
        let send = SendImapCommand::new(context, CommandCodec::new(), command);

        Self {
            state: State::Send(send),
            message: params.message,
            ir: params.ir,
            ensure_capabilities,
        }
    }

    /// Advances the coroutine.
    pub fn resume(&mut self, mut arg: Option<&[u8]>) -> ImapAuthAnonymousResult {
        loop {
            match &mut self.state {
                State::Send(coroutine) => {
                    let (context, bye, continuation_request, tagged, data, untagged) =
                        match coroutine.resume(arg.take()) {
                            SendImapCommandResult::WantsRead => {
                                break ImapAuthAnonymousResult::WantsRead;
                            }
                            SendImapCommandResult::WantsWrite(bytes) => {
                                break ImapAuthAnonymousResult::WantsWrite(bytes);
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
                                break ImapAuthAnonymousResult::Err {
                                    context,
                                    err: err.into(),
                                };
                            }
                        };

                    if let Some(bye) = bye {
                        let err = ImapAuthAnonymousError::Bye(bye.text.to_string());
                        return ImapAuthAnonymousResult::Err { context, err };
                    }

                    if continuation_request.is_some() {
                        if self.ir {
                            let err = ImapAuthAnonymousError::UnexpectedContinuationRequest;
                            return ImapAuthAnonymousResult::Err { context, err };
                        }

                        let message = self.message.take().unwrap().into_bytes();
                        let auth = AuthenticateData::r#continue(message);
                        let codec = AuthenticateDataCodec::new();
                        self.state = State::Continue(SendImapCommand::new(context, codec, auth));
                        continue;
                    }

                    if !self.ir {
                        let err = ImapAuthAnonymousError::MissingContinuationRequest;
                        return ImapAuthAnonymousResult::Err { context, err };
                    }

                    match finish(context, tagged, data, untagged) {
                        Ok(context) => {
                            if self.ensure_capabilities && context.capability.is_empty() {
                                self.state = State::Capability(ImapCapabilityGet::new(context));
                                continue;
                            }
                            return ImapAuthAnonymousResult::Ok { context };
                        }
                        Err((context, err)) => {
                            return ImapAuthAnonymousResult::Err { context, err };
                        }
                    }
                }
                State::Continue(coroutine) => {
                    let (context, bye, continuation_request, tagged, data, untagged) =
                        match coroutine.resume(arg.take()) {
                            SendImapCommandResult::WantsRead => {
                                break ImapAuthAnonymousResult::WantsRead;
                            }
                            SendImapCommandResult::WantsWrite(bytes) => {
                                break ImapAuthAnonymousResult::WantsWrite(bytes);
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
                                break ImapAuthAnonymousResult::Err {
                                    context,
                                    err: err.into(),
                                };
                            }
                        };

                    if let Some(bye) = bye {
                        let err = ImapAuthAnonymousError::Bye(bye.text.to_string());
                        return ImapAuthAnonymousResult::Err { context, err };
                    }

                    if continuation_request.is_some() {
                        let err = ImapAuthAnonymousError::UnexpectedContinuationRequest;
                        return ImapAuthAnonymousResult::Err { context, err };
                    }

                    match finish(context, tagged, data, untagged) {
                        Ok(context) => {
                            if self.ensure_capabilities && context.capability.is_empty() {
                                self.state = State::Capability(ImapCapabilityGet::new(context));
                                continue;
                            }
                            return ImapAuthAnonymousResult::Ok { context };
                        }
                        Err((context, err)) => {
                            return ImapAuthAnonymousResult::Err { context, err };
                        }
                    }
                }
                State::Capability(coroutine) => match coroutine.resume(arg.take()) {
                    ImapCapabilityGetResult::WantsRead => {
                        break ImapAuthAnonymousResult::WantsRead;
                    }
                    ImapCapabilityGetResult::WantsWrite(bytes) => {
                        break ImapAuthAnonymousResult::WantsWrite(bytes);
                    }
                    ImapCapabilityGetResult::Ok { context } => {
                        break ImapAuthAnonymousResult::Ok { context };
                    }
                    ImapCapabilityGetResult::Err { context, err } => {
                        break ImapAuthAnonymousResult::Err {
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
) -> Result<ImapContext, (ImapContext, ImapAuthAnonymousError)> {
    let Some(Tagged { body, .. }) = tagged else {
        let err = ImapAuthAnonymousError::MissingTagged;
        return Err((context, err));
    };

    let code = match body.kind {
        StatusKind::Ok => body.code,
        StatusKind::No => {
            let err = ImapAuthAnonymousError::No(body.text.to_string());
            return Err((context, err));
        }
        StatusKind::Bad => {
            let err = ImapAuthAnonymousError::Bad(body.text.to_string());
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
