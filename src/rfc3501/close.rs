//! I/O-free coroutine to send an IMAP CLOSE command.

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
pub enum ImapMailboxCloseError {
    #[error("IMAP CLOSE NO error: {0}")]
    No(String),
    #[error("IMAP CLOSE BAD error: {0}")]
    Bad(String),
    #[error("IMAP CLOSE BYE error: {0}")]
    Bye(String),

    #[error("No IMAP CLOSE tagged response returned by the server")]
    MissingTagged,

    #[error("Send IMAP CLOSE command error")]
    Send(#[from] SendImapCommandError),
}

/// Output emitted when the coroutine terminates its progression.
pub enum ImapMailboxCloseResult {
    Ok {
        context: ImapContext,
    },
    WantsRead,
    WantsWrite(Vec<u8>),
    Err {
        context: ImapContext,
        err: ImapMailboxCloseError,
    },
}

/// I/O-free coroutine to send an IMAP CLOSE command.
pub struct ImapMailboxClose {
    send: SendImapCommand<CommandCodec>,
}

impl ImapMailboxClose {
    /// Creates a new coroutine.
    pub fn new(mut context: ImapContext) -> Self {
        // SAFETY: tag is always valid
        let command = Command::new(context.generate_tag(), CommandBody::Close).unwrap();
        Self {
            send: SendImapCommand::new(context, CommandCodec::new(), command),
        }
    }

    /// Advances the coroutine.
    pub fn resume(&mut self, arg: Option<&[u8]>) -> ImapMailboxCloseResult {
        let (mut context, tagged, bye) = match self.send.resume(arg) {
            SendImapCommandResult::WantsRead => return ImapMailboxCloseResult::WantsRead,
            SendImapCommandResult::WantsWrite(bytes) => {
                return ImapMailboxCloseResult::WantsWrite(bytes);
            }
            SendImapCommandResult::Ok {
                context,
                tagged,
                bye,
                ..
            } => (context, tagged, bye),
            SendImapCommandResult::Err { context, err } => {
                return ImapMailboxCloseResult::Err {
                    context,
                    err: err.into(),
                };
            }
        };

        if let Some(bye) = bye {
            let err = ImapMailboxCloseError::Bye(bye.text.to_string());
            return ImapMailboxCloseResult::Err { context, err };
        }

        let Some(Tagged { body, .. }) = tagged else {
            let err = ImapMailboxCloseError::MissingTagged;
            return ImapMailboxCloseResult::Err { context, err };
        };

        match body.kind {
            StatusKind::Ok => {
                context.mailbox = ImapCurrentMailboxState::NotSelected;
                ImapMailboxCloseResult::Ok { context }
            }
            StatusKind::No => ImapMailboxCloseResult::Err {
                context,
                err: ImapMailboxCloseError::No(body.text.to_string()),
            },
            StatusKind::Bad => ImapMailboxCloseResult::Err {
                context,
                err: ImapMailboxCloseError::Bad(body.text.to_string()),
            },
        }
    }
}
