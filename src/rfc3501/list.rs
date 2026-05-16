//! I/O-free coroutine to send an IMAP LIST command.

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    imap_types::{
        command::{Command, CommandBody},
        core::QuotedChar,
        flag::FlagNameAttribute,
        mailbox::{ListMailbox, Mailbox},
        response::{Data, StatusKind, Tagged},
    },
};
use log::trace;
use thiserror::Error;

use crate::{context::ImapContext, send::*};

/// Output of the IMAP `LIST` (and `LSUB`) command: one row per matched
/// mailbox `(mailbox, hierarchy delimiter, attributes)`.
pub type ImapMailboxListing = Vec<(
    Mailbox<'static>,
    Option<QuotedChar>,
    Vec<FlagNameAttribute<'static>>,
)>;

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum ImapMailboxListError {
    #[error("IMAP LIST NO error: {0}")]
    No(String),
    #[error("IMAP LIST BAD error: {0}")]
    Bad(String),
    #[error("IMAP LIST BYE error: {0}")]
    Bye(String),

    #[error("No IMAP LIST tagged response returned by the server")]
    MissingTagged,

    #[error("Send IMAP LIST command error")]
    Send(#[from] SendImapCommandError),
}

/// Output emitted when the coroutine terminates its progression.
pub enum ImapMailboxListResult {
    Ok {
        context: ImapContext,
        mailboxes: ImapMailboxListing,
    },
    WantsRead,
    WantsWrite(Vec<u8>),
    Err {
        context: ImapContext,
        err: ImapMailboxListError,
    },
}

/// I/O-free coroutine to send an IMAP LIST command.
pub struct ImapMailboxList {
    send: SendImapCommand<CommandCodec>,
}

impl ImapMailboxList {
    /// Creates a new coroutine.
    pub fn new(
        mut context: ImapContext,
        reference: Mailbox<'static>,
        mailbox_wildcard: ListMailbox<'static>,
    ) -> Self {
        trace!("list IMAP mailboxes: {reference:?} {mailbox_wildcard:?}");

        let body = CommandBody::List {
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
    pub fn resume(&mut self, arg: Option<&[u8]>) -> ImapMailboxListResult {
        let (context, data, tagged, bye) = match self.send.resume(arg) {
            SendImapCommandResult::WantsRead => return ImapMailboxListResult::WantsRead,
            SendImapCommandResult::WantsWrite(bytes) => {
                return ImapMailboxListResult::WantsWrite(bytes);
            }
            SendImapCommandResult::Ok {
                context,
                data,
                tagged,
                bye,
                ..
            } => (context, data, tagged, bye),
            SendImapCommandResult::Err { context, err } => {
                return ImapMailboxListResult::Err {
                    context,
                    err: err.into(),
                };
            }
        };

        if let Some(bye) = bye {
            let err = ImapMailboxListError::Bye(bye.text.to_string());
            return ImapMailboxListResult::Err { context, err };
        }

        let Some(Tagged { body, .. }) = tagged else {
            let err = ImapMailboxListError::MissingTagged;
            return ImapMailboxListResult::Err { context, err };
        };

        let mut mailboxes = Vec::new();

        for data in data {
            if let Data::List {
                items,
                delimiter,
                mailbox,
            } = data
            {
                mailboxes.push((mailbox, delimiter, items));
            }
        }

        match body.kind {
            StatusKind::Ok => ImapMailboxListResult::Ok { context, mailboxes },
            StatusKind::No => ImapMailboxListResult::Err {
                context,
                err: ImapMailboxListError::No(body.text.to_string()),
            },
            StatusKind::Bad => ImapMailboxListResult::Err {
                context,
                err: ImapMailboxListError::Bad(body.text.to_string()),
            },
        }
    }
}
