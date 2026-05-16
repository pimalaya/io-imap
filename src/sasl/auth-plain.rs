//! I/O-free coroutine to authenticate an IMAP mailbox via PLAIN.

use core::mem;

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
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;

use crate::{context::ImapContext, rfc3501::capability::*, send::*};

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

/// Output emitted when the coroutine terminates its progression.
pub enum ImapAuthPlainResult {
    Ok {
        context: ImapContext,
    },
    WantsRead,
    WantsWrite(Vec<u8>),
    Err {
        context: ImapContext,
        err: ImapAuthPlainError,
    },
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
    ensure_capabilities: bool,
}

impl ImapAuthPlain {
    /// Creates a new coroutine. When `ensure_capabilities` is true and the
    /// server did not piggyback a capability list on the AUTHENTICATE tagged
    /// response, the coroutine drives an extra `CAPABILITY` round-trip
    /// before completing.
    pub fn new(
        mut context: ImapContext,
        params: ImapAuthPlainParams,
        ensure_capabilities: bool,
    ) -> Self {
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

        // SAFETY: tag is always valid
        let command = Command::new(context.generate_tag(), plain).unwrap();
        let send = SendImapCommand::new(context, CommandCodec::new(), command);

        Self {
            state: State::Send(send),
            payload,
            ir: params.ir,
            ensure_capabilities,
        }
    }

    /// Advances the coroutine.
    pub fn resume(&mut self, mut arg: Option<&[u8]>) -> ImapAuthPlainResult {
        loop {
            match &mut self.state {
                State::Send(coroutine) => {
                    let (context, bye, continuation_request, tagged, data, untagged) =
                        match coroutine.resume(arg.take()) {
                            SendImapCommandResult::WantsRead => {
                                break ImapAuthPlainResult::WantsRead;
                            }
                            SendImapCommandResult::WantsWrite(bytes) => {
                                break ImapAuthPlainResult::WantsWrite(bytes);
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
                                break ImapAuthPlainResult::Err {
                                    context,
                                    err: err.into(),
                                };
                            }
                        };

                    if let Some(bye) = bye {
                        let err = ImapAuthPlainError::Bye(bye.text.to_string());
                        return ImapAuthPlainResult::Err { context, err };
                    }

                    if continuation_request.is_some() {
                        if self.ir {
                            let err = ImapAuthPlainError::UnexpectedContinuationRequest;
                            return ImapAuthPlainResult::Err { context, err };
                        }

                        let payload = mem::take(&mut self.payload).into_bytes();
                        let auth = AuthenticateData::r#continue(payload);
                        let codec = AuthenticateDataCodec::new();
                        self.state = State::Continue(SendImapCommand::new(context, codec, auth));
                        continue;
                    }

                    if !self.ir {
                        let err = ImapAuthPlainError::MissingContinuationRequest;
                        return ImapAuthPlainResult::Err { context, err };
                    }

                    match finish(context, tagged, data, untagged) {
                        Ok(context) => {
                            if self.ensure_capabilities && context.capability.is_empty() {
                                self.state = State::Capability(ImapCapabilityGet::new(context));
                                continue;
                            }
                            return ImapAuthPlainResult::Ok { context };
                        }
                        Err((context, err)) => {
                            return ImapAuthPlainResult::Err { context, err };
                        }
                    }
                }
                State::Continue(coroutine) => {
                    let (context, bye, continuation_request, tagged, data, untagged) =
                        match coroutine.resume(arg.take()) {
                            SendImapCommandResult::WantsRead => {
                                break ImapAuthPlainResult::WantsRead;
                            }
                            SendImapCommandResult::WantsWrite(bytes) => {
                                break ImapAuthPlainResult::WantsWrite(bytes);
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
                                break ImapAuthPlainResult::Err {
                                    context,
                                    err: err.into(),
                                };
                            }
                        };

                    if let Some(bye) = bye {
                        let err = ImapAuthPlainError::Bye(bye.text.to_string());
                        return ImapAuthPlainResult::Err { context, err };
                    }

                    if continuation_request.is_some() {
                        let err = ImapAuthPlainError::UnexpectedContinuationRequest;
                        return ImapAuthPlainResult::Err { context, err };
                    }

                    match finish(context, tagged, data, untagged) {
                        Ok(context) => {
                            if self.ensure_capabilities && context.capability.is_empty() {
                                self.state = State::Capability(ImapCapabilityGet::new(context));
                                continue;
                            }
                            return ImapAuthPlainResult::Ok { context };
                        }
                        Err((context, err)) => {
                            return ImapAuthPlainResult::Err { context, err };
                        }
                    }
                }
                State::Capability(coroutine) => match coroutine.resume(arg.take()) {
                    ImapCapabilityGetResult::WantsRead => {
                        break ImapAuthPlainResult::WantsRead;
                    }
                    ImapCapabilityGetResult::WantsWrite(bytes) => {
                        break ImapAuthPlainResult::WantsWrite(bytes);
                    }
                    ImapCapabilityGetResult::Ok { context } => {
                        break ImapAuthPlainResult::Ok { context };
                    }
                    ImapCapabilityGetResult::Err { context, err } => {
                        break ImapAuthPlainResult::Err {
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
) -> Result<ImapContext, (ImapContext, ImapAuthPlainError)> {
    let Some(Tagged { body, .. }) = tagged else {
        let err = ImapAuthPlainError::MissingTagged;
        return Err((context, err));
    };

    let code = match body.kind {
        StatusKind::Ok => body.code,
        StatusKind::No => {
            let err = ImapAuthPlainError::No(body.text.to_string());
            return Err((context, err));
        }
        StatusKind::Bad => {
            let err = ImapAuthPlainError::Bad(body.text.to_string());
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
