//! I/O-free coroutine to send an IMAP RENAME command.

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    imap_types::{
        command::{Command, CommandBody},
        mailbox::Mailbox,
        response::{StatusKind, Tagged},
    },
};
use thiserror::Error;

use crate::{context::ImapContext, send::*};

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum ImapMailboxRenameError {
    #[error("IMAP RENAME NO error: {0}")]
    No(String),
    #[error("IMAP RENAME BAD error: {0}")]
    Bad(String),
    #[error("IMAP RENAME BYE error: {0}")]
    Bye(String),

    #[error("No IMAP RENAME tagged response returned by the server")]
    MissingTagged,

    #[error("Send IMAP RENAME command error")]
    Send(#[from] SendImapCommandError),
}

/// Output emitted when the coroutine terminates its progression.
pub enum ImapMailboxRenameResult {
    Ok {
        context: ImapContext,
    },
    WantsRead,
    WantsWrite(Vec<u8>),
    Err {
        context: ImapContext,
        err: ImapMailboxRenameError,
    },
}

/// I/O-free coroutine to send an IMAP RENAME command.
pub struct ImapMailboxRename {
    send: SendImapCommand<CommandCodec>,
}

impl ImapMailboxRename {
    /// Creates a new coroutine.
    pub fn new(mut context: ImapContext, from: Mailbox<'static>, to: Mailbox<'static>) -> Self {
        let body = CommandBody::Rename { from, to };
        // SAFETY: tag is always valid
        let command = Command::new(context.generate_tag(), body).unwrap();
        Self {
            send: SendImapCommand::new(context, CommandCodec::new(), command),
        }
    }

    /// Advances the coroutine.
    pub fn resume(&mut self, arg: Option<&[u8]>) -> ImapMailboxRenameResult {
        let (context, tagged, bye) = match self.send.resume(arg) {
            SendImapCommandResult::WantsRead => return ImapMailboxRenameResult::WantsRead,
            SendImapCommandResult::WantsWrite(bytes) => {
                return ImapMailboxRenameResult::WantsWrite(bytes);
            }
            SendImapCommandResult::Ok {
                context,
                tagged,
                bye,
                ..
            } => (context, tagged, bye),
            SendImapCommandResult::Err { context, err } => {
                return ImapMailboxRenameResult::Err {
                    context,
                    err: err.into(),
                };
            }
        };

        if let Some(bye) = bye {
            let err = ImapMailboxRenameError::Bye(bye.text.to_string());
            return ImapMailboxRenameResult::Err { context, err };
        }

        let Some(Tagged { body, .. }) = tagged else {
            let err = ImapMailboxRenameError::MissingTagged;
            return ImapMailboxRenameResult::Err { context, err };
        };

        match body.kind {
            StatusKind::Ok => ImapMailboxRenameResult::Ok { context },
            StatusKind::No => ImapMailboxRenameResult::Err {
                context,
                err: ImapMailboxRenameError::No(body.text.to_string()),
            },
            StatusKind::Bad => ImapMailboxRenameResult::Err {
                context,
                err: ImapMailboxRenameError::Bad(body.text.to_string()),
            },
        }
    }
}
