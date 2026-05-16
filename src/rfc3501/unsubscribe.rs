//! I/O-free coroutine to send an IMAP UNSUBSCRIBE command.

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
pub enum ImapMailboxUnsubscribeError {
    #[error("IMAP UNSUBSCRIBE NO error: {0}")]
    No(String),
    #[error("IMAP UNSUBSCRIBE BAD error: {0}")]
    Bad(String),
    #[error("IMAP UNSUBSCRIBE BYE error: {0}")]
    Bye(String),

    #[error("No IMAP UNSUBSCRIBE tagged response returned by the server")]
    MissingTagged,

    #[error("Send IMAP UNSUBSCRIBE command error")]
    Send(#[from] SendImapCommandError),
}

/// Output emitted when the coroutine terminates its progression.
pub enum ImapMailboxUnsubscribeResult {
    Ok {
        context: ImapContext,
    },
    WantsRead,
    WantsWrite(Vec<u8>),
    Err {
        context: ImapContext,
        err: ImapMailboxUnsubscribeError,
    },
}

/// I/O-free coroutine to send an IMAP UNSUBSCRIBE command.
pub struct ImapMailboxUnsubscribe {
    send: SendImapCommand<CommandCodec>,
}

impl ImapMailboxUnsubscribe {
    /// Creates a new coroutine.
    pub fn new(mut context: ImapContext, mailbox: Mailbox<'static>) -> Self {
        let body = CommandBody::Unsubscribe { mailbox };
        // SAFETY: tag is always valid
        let command = Command::new(context.generate_tag(), body).unwrap();
        Self {
            send: SendImapCommand::new(context, CommandCodec::new(), command),
        }
    }

    /// Advances the coroutine.
    pub fn resume(&mut self, arg: Option<&[u8]>) -> ImapMailboxUnsubscribeResult {
        let (context, tagged, bye) = match self.send.resume(arg) {
            SendImapCommandResult::WantsRead => return ImapMailboxUnsubscribeResult::WantsRead,
            SendImapCommandResult::WantsWrite(bytes) => {
                return ImapMailboxUnsubscribeResult::WantsWrite(bytes);
            }
            SendImapCommandResult::Ok {
                context,
                tagged,
                bye,
                ..
            } => (context, tagged, bye),
            SendImapCommandResult::Err { context, err } => {
                return ImapMailboxUnsubscribeResult::Err {
                    context,
                    err: err.into(),
                };
            }
        };

        if let Some(bye) = bye {
            let err = ImapMailboxUnsubscribeError::Bye(bye.text.to_string());
            return ImapMailboxUnsubscribeResult::Err { context, err };
        }

        let Some(Tagged { body, .. }) = tagged else {
            let err = ImapMailboxUnsubscribeError::MissingTagged;
            return ImapMailboxUnsubscribeResult::Err { context, err };
        };

        match body.kind {
            StatusKind::Ok => ImapMailboxUnsubscribeResult::Ok { context },
            StatusKind::No => ImapMailboxUnsubscribeResult::Err {
                context,
                err: ImapMailboxUnsubscribeError::No(body.text.to_string()),
            },
            StatusKind::Bad => ImapMailboxUnsubscribeResult::Err {
                context,
                err: ImapMailboxUnsubscribeError::Bad(body.text.to_string()),
            },
        }
    }
}
