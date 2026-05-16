//! I/O-free coroutine to send an IMAP ENABLE command.

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    imap_types::{
        command::{Command, CommandBody},
        core::Vec1,
        extensions::enable::CapabilityEnable,
        response::{Data, StatusKind, Tagged},
    },
};
use thiserror::Error;

use crate::{context::ImapContext, send::*};

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum ImapExtensionEnableError {
    #[error("IMAP ENABLE NO error: {0}")]
    No(String),
    #[error("IMAP ENABLE BAD error: {0}")]
    Bad(String),
    #[error("IMAP ENABLE BYE error: {0}")]
    Bye(String),

    #[error("No IMAP ENABLE tagged response returned by the server")]
    MissingTagged,

    #[error("Send IMAP ENABLE command error")]
    Send(#[from] SendImapCommandError),
}

/// Output emitted when the coroutine terminates its progression.
pub enum ImapExtensionEnableResult {
    Ok {
        context: ImapContext,
        enabled: Option<Vec<CapabilityEnable<'static>>>,
    },
    WantsRead,
    WantsWrite(Vec<u8>),
    Err {
        context: ImapContext,
        err: ImapExtensionEnableError,
    },
}

/// I/O-free coroutine to send an IMAP ENABLE command.
pub struct ImapExtensionEnable {
    send: SendImapCommand<CommandCodec>,
}

impl ImapExtensionEnable {
    /// Creates a new coroutine.
    pub fn new(mut context: ImapContext, capabilities: Vec1<CapabilityEnable<'static>>) -> Self {
        let body = CommandBody::Enable { capabilities };
        // SAFETY: tag is always valid
        let command = Command::new(context.generate_tag(), body).unwrap();
        Self {
            send: SendImapCommand::new(context, CommandCodec::new(), command),
        }
    }

    /// Advances the coroutine.
    pub fn resume(&mut self, arg: Option<&[u8]>) -> ImapExtensionEnableResult {
        let (context, data, tagged, bye) = match self.send.resume(arg) {
            SendImapCommandResult::WantsRead => return ImapExtensionEnableResult::WantsRead,
            SendImapCommandResult::WantsWrite(bytes) => {
                return ImapExtensionEnableResult::WantsWrite(bytes);
            }
            SendImapCommandResult::Ok {
                context,
                data,
                tagged,
                bye,
                ..
            } => (context, data, tagged, bye),
            SendImapCommandResult::Err { context, err } => {
                return ImapExtensionEnableResult::Err {
                    context,
                    err: err.into(),
                };
            }
        };

        if let Some(bye) = bye {
            let err = ImapExtensionEnableError::Bye(bye.text.to_string());
            return ImapExtensionEnableResult::Err { context, err };
        }

        let Some(Tagged { body, .. }) = tagged else {
            let err = ImapExtensionEnableError::MissingTagged;
            return ImapExtensionEnableResult::Err { context, err };
        };

        let mut enabled = None;

        for data in data {
            if let Data::Enabled { capabilities } = data {
                enabled = Some(capabilities);
            }
        }

        match body.kind {
            StatusKind::Ok => ImapExtensionEnableResult::Ok { context, enabled },
            StatusKind::No => ImapExtensionEnableResult::Err {
                context,
                err: ImapExtensionEnableError::No(body.text.to_string()),
            },
            StatusKind::Bad => ImapExtensionEnableResult::Err {
                context,
                err: ImapExtensionEnableError::Bad(body.text.to_string()),
            },
        }
    }
}
