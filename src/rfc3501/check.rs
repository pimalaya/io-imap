//! I/O-free coroutine to send an IMAP CHECK command.

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    imap_types::{
        command::{Command, CommandBody},
        response::{StatusKind, Tagged},
    },
};
use thiserror::Error;

use crate::{context::ImapContext, send::*};

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum ImapMailboxCheckError {
    #[error("IMAP CHECK NO error: {0}")]
    No(String),
    #[error("IMAP CHECK BAD error: {0}")]
    Bad(String),
    #[error("IMAP CHECK BYE error: {0}")]
    Bye(String),

    #[error("No IMAP CHECK tagged response returned by the server")]
    MissingTagged,

    #[error("Send IMAP CHECK command error")]
    Send(#[from] SendImapCommandError),
}

/// Output emitted when the coroutine terminates its progression.
pub enum ImapMailboxCheckResult {
    Ok {
        context: ImapContext,
    },
    WantsRead,
    WantsWrite(Vec<u8>),
    Err {
        context: ImapContext,
        err: ImapMailboxCheckError,
    },
}

/// I/O-free coroutine to send an IMAP CHECK command.
pub struct ImapMailboxCheck {
    send: SendImapCommand<CommandCodec>,
}

impl ImapMailboxCheck {
    /// Creates a new coroutine.
    pub fn new(mut context: ImapContext) -> Self {
        // SAFETY: tag is always valid
        let command = Command::new(context.generate_tag(), CommandBody::Check).unwrap();
        Self {
            send: SendImapCommand::new(context, CommandCodec::new(), command),
        }
    }

    /// Advances the coroutine.
    pub fn resume(&mut self, arg: Option<&[u8]>) -> ImapMailboxCheckResult {
        let (context, tagged, bye) = match self.send.resume(arg) {
            SendImapCommandResult::WantsRead => return ImapMailboxCheckResult::WantsRead,
            SendImapCommandResult::WantsWrite(bytes) => {
                return ImapMailboxCheckResult::WantsWrite(bytes);
            }
            SendImapCommandResult::Ok {
                context,
                tagged,
                bye,
                ..
            } => (context, tagged, bye),
            SendImapCommandResult::Err { context, err } => {
                return ImapMailboxCheckResult::Err {
                    context,
                    err: err.into(),
                };
            }
        };

        if let Some(bye) = bye {
            let err = ImapMailboxCheckError::Bye(bye.text.to_string());
            return ImapMailboxCheckResult::Err { context, err };
        }

        let Some(Tagged { body, .. }) = tagged else {
            let err = ImapMailboxCheckError::MissingTagged;
            return ImapMailboxCheckResult::Err { context, err };
        };

        match body.kind {
            StatusKind::Ok => ImapMailboxCheckResult::Ok { context },
            StatusKind::No => ImapMailboxCheckResult::Err {
                context,
                err: ImapMailboxCheckError::No(body.text.to_string()),
            },
            StatusKind::Bad => ImapMailboxCheckResult::Err {
                context,
                err: ImapMailboxCheckError::Bad(body.text.to_string()),
            },
        }
    }
}
