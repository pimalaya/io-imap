//! I/O-free coroutine to send an IMAP ID command.

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    imap_types::{
        command::{Command, CommandBody},
        core::{IString, NString},
        response::{Data, StatusKind, Tagged},
    },
};
use thiserror::Error;

use crate::{context::ImapContext, send::*};

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum ImapServerIdError {
    #[error("IMAP ID NO error: {0}")]
    No(String),
    #[error("IMAP ID BAD error: {0}")]
    Bad(String),
    #[error("IMAP ID BYE error: {0}")]
    Bye(String),

    #[error("No IMAP ID tagged response returned by the server")]
    MissingTagged,

    #[error("Send IMAP ID command error")]
    Send(#[from] SendImapCommandError),
}

/// Output emitted when the coroutine terminates its progression.
pub enum ImapServerIdResult {
    Ok {
        context: ImapContext,
        server_id: Option<Vec<(IString<'static>, NString<'static>)>>,
    },
    WantsRead,
    WantsWrite(Vec<u8>),
    Err {
        context: ImapContext,
        err: ImapServerIdError,
    },
}

/// I/O-free coroutine to send an IMAP ID command.
pub struct ImapServerId {
    send: SendImapCommand<CommandCodec>,
}

impl ImapServerId {
    /// Creates a new coroutine.
    pub fn new(
        mut context: ImapContext,
        parameters: Option<Vec<(IString<'static>, NString<'static>)>>,
    ) -> Self {
        let body = CommandBody::Id { parameters };
        // SAFETY: tag is always valid
        let command = Command::new(context.generate_tag(), body).unwrap();
        Self {
            send: SendImapCommand::new(context, CommandCodec::new(), command),
        }
    }

    /// Advances the coroutine.
    pub fn resume(&mut self, arg: Option<&[u8]>) -> ImapServerIdResult {
        let (context, data, tagged, bye) = match self.send.resume(arg) {
            SendImapCommandResult::WantsRead => return ImapServerIdResult::WantsRead,
            SendImapCommandResult::WantsWrite(bytes) => {
                return ImapServerIdResult::WantsWrite(bytes);
            }
            SendImapCommandResult::Ok {
                context,
                data,
                tagged,
                bye,
                ..
            } => (context, data, tagged, bye),
            SendImapCommandResult::Err { context, err } => {
                return ImapServerIdResult::Err {
                    context,
                    err: err.into(),
                };
            }
        };

        if let Some(bye) = bye {
            let err = ImapServerIdError::Bye(bye.text.to_string());
            return ImapServerIdResult::Err { context, err };
        }

        let Some(Tagged { body, .. }) = tagged else {
            let err = ImapServerIdError::MissingTagged;
            return ImapServerIdResult::Err { context, err };
        };

        let mut server_id = None;

        for data in data {
            if let Data::Id { parameters } = data {
                server_id = parameters;
            }
        }

        match body.kind {
            StatusKind::Ok => ImapServerIdResult::Ok { context, server_id },
            StatusKind::No => ImapServerIdResult::Err {
                context,
                err: ImapServerIdError::No(body.text.to_string()),
            },
            StatusKind::Bad => ImapServerIdResult::Err {
                context,
                err: ImapServerIdError::Bad(body.text.to_string()),
            },
        }
    }
}
