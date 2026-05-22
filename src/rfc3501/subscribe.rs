//! I/O-free coroutine to send an IMAP SUBSCRIBE command.

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

use crate::{context::ImapContext, rfc3501::mailbox::encode_inplace, send::*};

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum ImapMailboxSubscribeError {
    #[error("IMAP SUBSCRIBE NO error: {0}")]
    No(String),
    #[error("IMAP SUBSCRIBE BAD error: {0}")]
    Bad(String),
    #[error("IMAP SUBSCRIBE BYE error: {0}")]
    Bye(String),

    #[error("No IMAP SUBSCRIBE tagged response returned by the server")]
    MissingTagged,

    #[error("Send IMAP SUBSCRIBE command error")]
    Send(#[from] SendImapCommandError),
}

/// Output emitted when the coroutine terminates its progression.
pub enum ImapMailboxSubscribeResult {
    Ok {
        context: ImapContext,
    },
    WantsRead,
    WantsWrite(Vec<u8>),
    Err {
        context: ImapContext,
        err: ImapMailboxSubscribeError,
    },
}

/// I/O-free coroutine to send an IMAP SUBSCRIBE command.
pub struct ImapMailboxSubscribe {
    send: SendImapCommand<CommandCodec>,
}

impl ImapMailboxSubscribe {
    /// Creates a new coroutine.
    pub fn new(mut context: ImapContext, mut mailbox: Mailbox<'static>) -> Self {
        encode_inplace(&mut mailbox);
        let body = CommandBody::Subscribe { mailbox };
        // SAFETY: tag is always valid
        let command = Command::new(context.generate_tag(), body).unwrap();
        Self {
            send: SendImapCommand::new(context, CommandCodec::new(), command),
        }
    }

    /// Advances the coroutine.
    pub fn resume(&mut self, arg: Option<&[u8]>) -> ImapMailboxSubscribeResult {
        let (context, tagged, bye) = match self.send.resume(arg) {
            SendImapCommandResult::WantsRead => return ImapMailboxSubscribeResult::WantsRead,
            SendImapCommandResult::WantsWrite(bytes) => {
                return ImapMailboxSubscribeResult::WantsWrite(bytes);
            }
            SendImapCommandResult::Ok {
                context,
                tagged,
                bye,
                ..
            } => (context, tagged, bye),
            SendImapCommandResult::Err { context, err } => {
                return ImapMailboxSubscribeResult::Err {
                    context,
                    err: err.into(),
                };
            }
        };

        if let Some(bye) = bye {
            let err = ImapMailboxSubscribeError::Bye(bye.text.to_string());
            return ImapMailboxSubscribeResult::Err { context, err };
        }

        let Some(Tagged { body, .. }) = tagged else {
            let err = ImapMailboxSubscribeError::MissingTagged;
            return ImapMailboxSubscribeResult::Err { context, err };
        };

        match body.kind {
            StatusKind::Ok => ImapMailboxSubscribeResult::Ok { context },
            StatusKind::No => ImapMailboxSubscribeResult::Err {
                context,
                err: ImapMailboxSubscribeError::No(body.text.to_string()),
            },
            StatusKind::Bad => ImapMailboxSubscribeResult::Err {
                context,
                err: ImapMailboxSubscribeError::Bad(body.text.to_string()),
            },
        }
    }
}
