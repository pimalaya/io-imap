//! I/O-free coroutine to send an IMAP LSUB command.

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    imap_types::{
        command::{Command, CommandBody},
        mailbox::{ListMailbox, Mailbox},
        response::{Data, StatusKind, Tagged},
    },
};
use log::trace;
use thiserror::Error;

use crate::{
    context::ImapContext,
    rfc3501::{
        list::ImapMailboxListing,
        mailbox::{decode_inplace, encode_inplace},
    },
    send::*,
};

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum ImapMailboxLsubError {
    #[error("IMAP LSUB NO error: {0}")]
    No(String),
    #[error("IMAP LSUB BAD error: {0}")]
    Bad(String),
    #[error("IMAP LSUB BYE error: {0}")]
    Bye(String),

    #[error("No IMAP LSUB tagged response returned by the server")]
    MissingTagged,

    #[error("Send IMAP LSUB command error")]
    Send(#[from] SendImapCommandError),
}

/// Output emitted when the coroutine terminates its progression.
pub enum ImapMailboxLsubResult {
    Ok {
        context: ImapContext,
        mailboxes: ImapMailboxListing,
    },
    WantsRead,
    WantsWrite(Vec<u8>),
    Err {
        context: ImapContext,
        err: ImapMailboxLsubError,
    },
}

/// I/O-free coroutine to send an IMAP LSUB command.
pub struct ImapMailboxLsub {
    send: SendImapCommand<CommandCodec>,
}

impl ImapMailboxLsub {
    /// Creates a new coroutine.
    pub fn new(
        mut context: ImapContext,
        mut reference: Mailbox<'static>,
        mailbox_wildcard: ListMailbox<'static>,
    ) -> Self {
        trace!("lsub IMAP mailboxes: {reference:?} {mailbox_wildcard:?}");
        encode_inplace(&mut reference);

        let body = CommandBody::Lsub {
            reference,
            mailbox_wildcard,
        };
        // SAFETY: tag is always valid
        let command = Command::new(context.generate_tag(), body).unwrap();
        Self {
            send: SendImapCommand::new(context, CommandCodec::new(), command),
        }
    }

    /// Advances the coroutine.
    pub fn resume(&mut self, arg: Option<&[u8]>) -> ImapMailboxLsubResult {
        let (context, data, tagged, bye) = match self.send.resume(arg) {
            SendImapCommandResult::WantsRead => return ImapMailboxLsubResult::WantsRead,
            SendImapCommandResult::WantsWrite(bytes) => {
                return ImapMailboxLsubResult::WantsWrite(bytes);
            }
            SendImapCommandResult::Ok {
                context,
                data,
                tagged,
                bye,
                ..
            } => (context, data, tagged, bye),
            SendImapCommandResult::Err { context, err } => {
                return ImapMailboxLsubResult::Err {
                    context,
                    err: err.into(),
                };
            }
        };

        if let Some(bye) = bye {
            let err = ImapMailboxLsubError::Bye(bye.text.to_string());
            return ImapMailboxLsubResult::Err { context, err };
        }

        let Some(Tagged { body, .. }) = tagged else {
            let err = ImapMailboxLsubError::MissingTagged;
            return ImapMailboxLsubResult::Err { context, err };
        };

        let mut mailboxes = Vec::new();

        for data in data {
            if let Data::Lsub {
                items,
                delimiter,
                mailbox,
            } = data
            {
                let mut mailbox = mailbox;
                decode_inplace(&mut mailbox);
                mailboxes.push((mailbox, delimiter, items));
            }
        }

        match body.kind {
            StatusKind::Ok => ImapMailboxLsubResult::Ok { context, mailboxes },
            StatusKind::No => ImapMailboxLsubResult::Err {
                context,
                err: ImapMailboxLsubError::No(body.text.to_string()),
            },
            StatusKind::Bad => ImapMailboxLsubResult::Err {
                context,
                err: ImapMailboxLsubError::Bad(body.text.to_string()),
            },
        }
    }
}
