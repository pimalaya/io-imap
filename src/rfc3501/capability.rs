//! I/O-free coroutine to get capabilities of an IMAP server.

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    imap_types::{
        command::{Command, CommandBody},
        response::{Code, Data, StatusBody, StatusKind, Tagged},
    },
};
use thiserror::Error;

use crate::{context::ImapContext, send::*};

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum ImapCapabilityGetError {
    #[error("IMAP CAPABILITY NO error: {0}")]
    No(String),
    #[error("IMAP CAPABILITY BAD error: {0}")]
    Bad(String),
    #[error("IMAP CAPABILITY BYE error: {0}")]
    Bye(String),

    #[error("No CAPABILITY tagged response returned by the IMAP server")]
    ExpectedTagged,
    #[error("No CAPABILITY returned by the IMAP server")]
    ExpectedCapability,

    #[error("Send IMAP CAPABILITY command error")]
    Send(#[from] SendImapCommandError),
}

/// Output emitted when the coroutine terminates its progression.
pub enum ImapCapabilityGetResult {
    Ok {
        context: ImapContext,
    },
    WantsRead,
    WantsWrite(Vec<u8>),
    Err {
        context: ImapContext,
        err: ImapCapabilityGetError,
    },
}

/// I/O-free coroutine to get capabilities of an IMAP server.
pub struct ImapCapabilityGet {
    send: SendImapCommand<CommandCodec>,
}

impl ImapCapabilityGet {
    /// Creates a new coroutine.
    pub fn new(mut context: ImapContext) -> Self {
        // SAFETY: tag is always valid
        let command = Command::new(context.generate_tag(), CommandBody::Capability).unwrap();

        Self {
            send: SendImapCommand::new(context, CommandCodec::new(), command),
        }
    }

    /// Advances the coroutine.
    pub fn resume(&mut self, arg: Option<&[u8]>) -> ImapCapabilityGetResult {
        let (mut context, bye, tagged, data, untagged) = match self.send.resume(arg) {
            SendImapCommandResult::WantsRead => return ImapCapabilityGetResult::WantsRead,
            SendImapCommandResult::WantsWrite(bytes) => {
                return ImapCapabilityGetResult::WantsWrite(bytes);
            }
            SendImapCommandResult::Ok {
                context,
                bye,
                tagged,
                data,
                untagged,
                ..
            } => (context, bye, tagged, data, untagged),
            SendImapCommandResult::Err { context, err } => {
                return ImapCapabilityGetResult::Err {
                    context,
                    err: err.into(),
                };
            }
        };

        if let Some(bye) = bye {
            let err = ImapCapabilityGetError::Bye(bye.text.to_string());
            return ImapCapabilityGetResult::Err { context, err };
        }

        let Some(Tagged { body, .. }) = tagged else {
            let err = ImapCapabilityGetError::ExpectedTagged;
            return ImapCapabilityGetResult::Err { context, err };
        };

        let code = match body.kind {
            StatusKind::Ok => body.code,
            StatusKind::No => {
                let err = ImapCapabilityGetError::No(body.text.to_string());
                return ImapCapabilityGetResult::Err { context, err };
            }
            StatusKind::Bad => {
                let err = ImapCapabilityGetError::Bad(body.text.to_string());
                return ImapCapabilityGetResult::Err { context, err };
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

        let Some(capability) = new_capability else {
            let err = ImapCapabilityGetError::ExpectedCapability;
            return ImapCapabilityGetResult::Err { context, err };
        };

        context.capability = capability.into_iter().collect();

        ImapCapabilityGetResult::Ok { context }
    }
}
