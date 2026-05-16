//! I/O-free coroutine to send an IMAP EXPUNGE command.

use core::num::NonZeroU32;

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    imap_types::{
        command::{Command, CommandBody},
        response::{Data, StatusKind, Tagged},
    },
};
use thiserror::Error;

use crate::{context::ImapContext, send::*};

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum ImapMailboxExpungeError {
    #[error("IMAP EXPUNGE NO error: {0}")]
    No(String),
    #[error("IMAP EXPUNGE BAD error: {0}")]
    Bad(String),
    #[error("IMAP EXPUNGE BYE error: {0}")]
    Bye(String),

    #[error("No IMAP EXPUNGE tagged response returned by the server")]
    MissingTagged,

    #[error("Send IMAP EXPUNGE command error")]
    Send(#[from] SendImapCommandError),
}

/// Output emitted when the coroutine terminates its progression.
pub enum ImapMailboxExpungeResult {
    Ok {
        context: ImapContext,
        expunged: Vec<NonZeroU32>,
    },
    WantsRead,
    WantsWrite(Vec<u8>),
    Err {
        context: ImapContext,
        err: ImapMailboxExpungeError,
    },
}

/// I/O-free coroutine to send an IMAP EXPUNGE command.
pub struct ImapMailboxExpunge {
    send: SendImapCommand<CommandCodec>,
}

impl ImapMailboxExpunge {
    /// Creates a new coroutine.
    pub fn new(mut context: ImapContext) -> Self {
        // SAFETY: tag is always valid
        let command = Command::new(context.generate_tag(), CommandBody::Expunge).unwrap();
        Self {
            send: SendImapCommand::new(context, CommandCodec::new(), command),
        }
    }

    /// Advances the coroutine.
    pub fn resume(&mut self, arg: Option<&[u8]>) -> ImapMailboxExpungeResult {
        let (context, data, tagged, bye) = match self.send.resume(arg) {
            SendImapCommandResult::WantsRead => return ImapMailboxExpungeResult::WantsRead,
            SendImapCommandResult::WantsWrite(bytes) => {
                return ImapMailboxExpungeResult::WantsWrite(bytes);
            }
            SendImapCommandResult::Ok {
                context,
                data,
                tagged,
                bye,
                ..
            } => (context, data, tagged, bye),
            SendImapCommandResult::Err { context, err } => {
                return ImapMailboxExpungeResult::Err {
                    context,
                    err: err.into(),
                };
            }
        };

        if let Some(bye) = bye {
            let err = ImapMailboxExpungeError::Bye(bye.text.to_string());
            return ImapMailboxExpungeResult::Err { context, err };
        }

        let Some(Tagged { body, .. }) = tagged else {
            let err = ImapMailboxExpungeError::MissingTagged;
            return ImapMailboxExpungeResult::Err { context, err };
        };

        let mut expunged = Vec::new();

        for data in data {
            if let Data::Expunge(seq) = data {
                expunged.push(seq);
            }
        }

        match body.kind {
            StatusKind::Ok => ImapMailboxExpungeResult::Ok { context, expunged },
            StatusKind::No => ImapMailboxExpungeResult::Err {
                context,
                err: ImapMailboxExpungeError::No(body.text.to_string()),
            },
            StatusKind::Bad => ImapMailboxExpungeResult::Err {
                context,
                err: ImapMailboxExpungeError::Bad(body.text.to_string()),
            },
        }
    }
}
