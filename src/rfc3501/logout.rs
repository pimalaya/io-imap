//! I/O-free coroutine to send an IMAP LOGOUT command.

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
pub enum ImapLogoutError {
    #[error("IMAP LOGOUT NO error: {0}")]
    No(String),
    #[error("IMAP LOGOUT BAD error: {0}")]
    Bad(String),

    #[error("No IMAP LOGOUT tagged response returned by the server")]
    MissingTagged,
    #[error("No IMAP LOGOUT BYE response returned by the server")]
    MissingBye,

    #[error("Send IMAP LOGOUT command error")]
    Send(#[from] SendImapCommandError),
}

/// Output emitted when the coroutine terminates its progression.
pub enum ImapLogoutResult {
    Ok {
        context: ImapContext,
    },
    WantsRead,
    WantsWrite(Vec<u8>),
    Err {
        context: ImapContext,
        err: ImapLogoutError,
    },
}

/// I/O-free coroutine to send an IMAP LOGOUT command.
pub struct ImapLogout {
    send: SendImapCommand<CommandCodec>,
}

impl ImapLogout {
    /// Creates a new coroutine.
    pub fn new(mut context: ImapContext) -> Self {
        // SAFETY: tag is always valid
        let command = Command::new(context.generate_tag(), CommandBody::Logout).unwrap();
        Self {
            send: SendImapCommand::new(context, CommandCodec::new(), command),
        }
    }

    /// Advances the coroutine.
    pub fn resume(&mut self, arg: Option<&[u8]>) -> ImapLogoutResult {
        let (mut context, tagged, bye) = match self.send.resume(arg) {
            SendImapCommandResult::WantsRead => return ImapLogoutResult::WantsRead,
            SendImapCommandResult::WantsWrite(bytes) => {
                return ImapLogoutResult::WantsWrite(bytes);
            }
            SendImapCommandResult::Ok {
                context,
                tagged,
                bye,
                ..
            } => (context, tagged, bye),
            SendImapCommandResult::Err { context, err } => {
                return ImapLogoutResult::Err {
                    context,
                    err: err.into(),
                };
            }
        };

        if bye.is_none() {
            let err = ImapLogoutError::MissingBye;
            return ImapLogoutResult::Err { context, err };
        }

        let Some(Tagged { body, .. }) = tagged else {
            let err = ImapLogoutError::MissingTagged;
            return ImapLogoutResult::Err { context, err };
        };

        match body.kind {
            StatusKind::Ok => {
                context.authenticated = false;
                context.mailbox = ImapCurrentMailboxState::NotSelected;
                ImapLogoutResult::Ok { context }
            }
            StatusKind::No => ImapLogoutResult::Err {
                context,
                err: ImapLogoutError::No(body.text.to_string()),
            },
            StatusKind::Bad => ImapLogoutResult::Err {
                context,
                err: ImapLogoutError::Bad(body.text.to_string()),
            },
        }
    }
}
