//! I/O-free coroutine to send an IMAP DELETE command.

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
pub enum ImapMailboxDeleteError {
    #[error("IMAP DELETE NO error: {0}")]
    No(String),
    #[error("IMAP DELETE BAD error: {0}")]
    Bad(String),
    #[error("IMAP DELETE BYE error: {0}")]
    Bye(String),

    #[error("No IMAP DELETE tagged response returned by the server")]
    MissingTagged,

    #[error("Send IMAP DELETE command error")]
    Send(#[from] SendImapCommandError),
}

/// Output emitted when the coroutine terminates its progression.
pub enum ImapMailboxDeleteResult {
    Ok {
        context: ImapContext,
    },
    WantsRead,
    WantsWrite(Vec<u8>),
    Err {
        context: ImapContext,
        err: ImapMailboxDeleteError,
    },
}

/// I/O-free coroutine to send an IMAP DELETE command.
pub struct ImapMailboxDelete {
    send: SendImapCommand<CommandCodec>,
}

impl ImapMailboxDelete {
    /// Creates a new coroutine.
    pub fn new(mut context: ImapContext, mailbox: Mailbox<'static>) -> Self {
        let body = CommandBody::Delete { mailbox };
        // SAFETY: tag is always valid
        let command = Command::new(context.generate_tag(), body).unwrap();
        Self {
            send: SendImapCommand::new(context, CommandCodec::new(), command),
        }
    }

    /// Advances the coroutine.
    pub fn resume(&mut self, arg: Option<&[u8]>) -> ImapMailboxDeleteResult {
        let (context, tagged, bye) = match self.send.resume(arg) {
            SendImapCommandResult::WantsRead => return ImapMailboxDeleteResult::WantsRead,
            SendImapCommandResult::WantsWrite(bytes) => {
                return ImapMailboxDeleteResult::WantsWrite(bytes);
            }
            SendImapCommandResult::Ok {
                context,
                tagged,
                bye,
                ..
            } => (context, tagged, bye),
            SendImapCommandResult::Err { context, err } => {
                return ImapMailboxDeleteResult::Err {
                    context,
                    err: err.into(),
                };
            }
        };

        if let Some(bye) = bye {
            let err = ImapMailboxDeleteError::Bye(bye.text.to_string());
            return ImapMailboxDeleteResult::Err { context, err };
        }

        let Some(Tagged { body, .. }) = tagged else {
            let err = ImapMailboxDeleteError::MissingTagged;
            return ImapMailboxDeleteResult::Err { context, err };
        };

        match body.kind {
            StatusKind::Ok => ImapMailboxDeleteResult::Ok { context },
            StatusKind::No => ImapMailboxDeleteResult::Err {
                context,
                err: ImapMailboxDeleteError::No(body.text.to_string()),
            },
            StatusKind::Bad => ImapMailboxDeleteResult::Err {
                context,
                err: ImapMailboxDeleteError::Bad(body.text.to_string()),
            },
        }
    }
}
