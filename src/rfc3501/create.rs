//! I/O-free coroutine to send an IMAP CREATE command.

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
pub enum ImapMailboxCreateError {
    #[error("IMAP CREATE NO error: {0}")]
    No(String),
    #[error("IMAP CREATE BAD error: {0}")]
    Bad(String),
    #[error("IMAP CREATE BYE error: {0}")]
    Bye(String),

    #[error("No IMAP CREATE tagged response returned by the server")]
    MissingTagged,

    #[error("Send IMAP CREATE command error")]
    Send(#[from] SendImapCommandError),
}

/// Output emitted when the coroutine terminates its progression.
pub enum ImapMailboxCreateResult {
    Ok {
        context: ImapContext,
    },
    WantsRead,
    WantsWrite(Vec<u8>),
    Err {
        context: ImapContext,
        err: ImapMailboxCreateError,
    },
}

/// I/O-free coroutine to send an IMAP CREATE command.
pub struct ImapMailboxCreate {
    send: SendImapCommand<CommandCodec>,
}

impl ImapMailboxCreate {
    /// Creates a new coroutine.
    pub fn new(mut context: ImapContext, mailbox: Mailbox<'static>) -> Self {
        let body = CommandBody::Create { mailbox };
        // SAFETY: tag is always valid
        let command = Command::new(context.generate_tag(), body).unwrap();
        Self {
            send: SendImapCommand::new(context, CommandCodec::new(), command),
        }
    }

    /// Advances the coroutine.
    pub fn resume(&mut self, arg: Option<&[u8]>) -> ImapMailboxCreateResult {
        let (context, tagged, bye) = match self.send.resume(arg) {
            SendImapCommandResult::WantsRead => return ImapMailboxCreateResult::WantsRead,
            SendImapCommandResult::WantsWrite(bytes) => {
                return ImapMailboxCreateResult::WantsWrite(bytes);
            }
            SendImapCommandResult::Ok {
                context,
                tagged,
                bye,
                ..
            } => (context, tagged, bye),
            SendImapCommandResult::Err { context, err } => {
                return ImapMailboxCreateResult::Err {
                    context,
                    err: err.into(),
                };
            }
        };

        if let Some(bye) = bye {
            let err = ImapMailboxCreateError::Bye(bye.text.to_string());
            return ImapMailboxCreateResult::Err { context, err };
        }

        let Some(Tagged { body, .. }) = tagged else {
            let err = ImapMailboxCreateError::MissingTagged;
            return ImapMailboxCreateResult::Err { context, err };
        };

        match body.kind {
            StatusKind::Ok => ImapMailboxCreateResult::Ok { context },
            StatusKind::No => ImapMailboxCreateResult::Err {
                context,
                err: ImapMailboxCreateError::No(body.text.to_string()),
            },
            StatusKind::Bad => ImapMailboxCreateResult::Err {
                context,
                err: ImapMailboxCreateError::Bad(body.text.to_string()),
            },
        }
    }
}
