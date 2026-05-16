//! I/O-free coroutine to send an IMAP UNSELECT command.

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    imap_types::{
        command::{Command, CommandBody},
        response::{StatusKind, Tagged},
    },
};
use thiserror::Error;

use crate::{
    context::{ImapContext, ImapCurrentMailboxState},
    send::*,
};

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum ImapMailboxUnselectError {
    #[error("IMAP UNSELECT NO error: {0}")]
    No(String),
    #[error("IMAP UNSELECT BAD error: {0}")]
    Bad(String),
    #[error("IMAP UNSELECT BYE error: {0}")]
    Bye(String),

    #[error("No IMAP UNSELECT tagged response returned by the server")]
    MissingTagged,

    #[error("Send IMAP UNSELECT command error")]
    Send(#[from] SendImapCommandError),
}

/// Output emitted when the coroutine terminates its progression.
pub enum ImapMailboxUnselectResult {
    Ok {
        context: ImapContext,
    },
    WantsRead,
    WantsWrite(Vec<u8>),
    Err {
        context: ImapContext,
        err: ImapMailboxUnselectError,
    },
}

/// I/O-free coroutine to send an IMAP UNSELECT command.
pub struct ImapMailboxUnselect {
    send: SendImapCommand<CommandCodec>,
}

impl ImapMailboxUnselect {
    /// Creates a new coroutine.
    pub fn new(mut context: ImapContext) -> Self {
        // SAFETY: tag is always valid
        let command = Command::new(context.generate_tag(), CommandBody::Unselect).unwrap();
        Self {
            send: SendImapCommand::new(context, CommandCodec::new(), command),
        }
    }

    /// Advances the coroutine.
    pub fn resume(&mut self, arg: Option<&[u8]>) -> ImapMailboxUnselectResult {
        let (mut context, tagged, bye) = match self.send.resume(arg) {
            SendImapCommandResult::WantsRead => return ImapMailboxUnselectResult::WantsRead,
            SendImapCommandResult::WantsWrite(bytes) => {
                return ImapMailboxUnselectResult::WantsWrite(bytes);
            }
            SendImapCommandResult::Ok {
                context,
                tagged,
                bye,
                ..
            } => (context, tagged, bye),
            SendImapCommandResult::Err { context, err } => {
                return ImapMailboxUnselectResult::Err {
                    context,
                    err: err.into(),
                };
            }
        };

        if let Some(bye) = bye {
            let err = ImapMailboxUnselectError::Bye(bye.text.to_string());
            return ImapMailboxUnselectResult::Err { context, err };
        }

        let Some(Tagged { body, .. }) = tagged else {
            let err = ImapMailboxUnselectError::MissingTagged;
            return ImapMailboxUnselectResult::Err { context, err };
        };

        match body.kind {
            StatusKind::Ok => {
                context.mailbox = ImapCurrentMailboxState::NotSelected;
                ImapMailboxUnselectResult::Ok { context }
            }
            StatusKind::No => ImapMailboxUnselectResult::Err {
                context,
                err: ImapMailboxUnselectError::No(body.text.to_string()),
            },
            StatusKind::Bad => ImapMailboxUnselectResult::Err {
                context,
                err: ImapMailboxUnselectError::Bad(body.text.to_string()),
            },
        }
    }
}
