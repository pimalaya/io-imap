//! I/O-free coroutine to send an IMAP NOOP command.

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
pub enum ImapNoopError {
    #[error("IMAP NOOP NO error: {0}")]
    No(String),
    #[error("IMAP NOOP BAD error: {0}")]
    Bad(String),
    #[error("IMAP NOOP BYE error: {0}")]
    Bye(String),

    #[error("No IMAP NOOP tagged response returned by the server")]
    MissingTagged,

    #[error("Send IMAP NOOP command error")]
    Send(#[from] SendImapCommandError),
}

/// Output emitted when the coroutine terminates its progression.
pub enum ImapNoopResult {
    Ok {
        context: ImapContext,
    },
    WantsRead,
    WantsWrite(Vec<u8>),
    Err {
        context: ImapContext,
        err: ImapNoopError,
    },
}

/// I/O-free coroutine to send an IMAP NOOP command.
pub struct ImapNoop {
    send: SendImapCommand<CommandCodec>,
}

impl ImapNoop {
    /// Creates a new coroutine.
    pub fn new(mut context: ImapContext) -> Self {
        // SAFETY: tag is always valid
        let command = Command::new(context.generate_tag(), CommandBody::Noop).unwrap();
        Self {
            send: SendImapCommand::new(context, CommandCodec::new(), command),
        }
    }

    /// Advances the coroutine.
    pub fn resume(&mut self, arg: Option<&[u8]>) -> ImapNoopResult {
        let (context, tagged, bye) = match self.send.resume(arg) {
            SendImapCommandResult::WantsRead => return ImapNoopResult::WantsRead,
            SendImapCommandResult::WantsWrite(bytes) => return ImapNoopResult::WantsWrite(bytes),
            SendImapCommandResult::Ok {
                context,
                tagged,
                bye,
                ..
            } => (context, tagged, bye),
            SendImapCommandResult::Err { context, err } => {
                return ImapNoopResult::Err {
                    context,
                    err: err.into(),
                };
            }
        };

        if let Some(bye) = bye {
            let err = ImapNoopError::Bye(bye.text.to_string());
            return ImapNoopResult::Err { context, err };
        }

        let Some(Tagged { body, .. }) = tagged else {
            let err = ImapNoopError::MissingTagged;
            return ImapNoopResult::Err { context, err };
        };

        match body.kind {
            StatusKind::Ok => ImapNoopResult::Ok { context },
            StatusKind::No => ImapNoopResult::Err {
                context,
                err: ImapNoopError::No(body.text.to_string()),
            },
            StatusKind::Bad => ImapNoopResult::Err {
                context,
                err: ImapNoopError::Bad(body.text.to_string()),
            },
        }
    }
}
