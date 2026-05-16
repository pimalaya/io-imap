//! I/O-free coroutine to send an IMAP STATUS command.

use alloc::{borrow::Cow, string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    imap_types::{
        command::{Command, CommandBody},
        mailbox::Mailbox,
        response::{Data, StatusKind, Tagged},
        status::{StatusDataItem, StatusDataItemName},
    },
};
use log::trace;
use thiserror::Error;

use crate::{context::ImapContext, send::*};

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum ImapMailboxStatusError {
    #[error("IMAP STATUS NO error: {0}")]
    No(String),
    #[error("IMAP STATUS BAD error: {0}")]
    Bad(String),
    #[error("IMAP STATUS BYE error: {0}")]
    Bye(String),

    #[error("No IMAP STATUS tagged response returned by the server")]
    MissingTagged,

    #[error("Send IMAP STATUS command error")]
    Send(#[from] SendImapCommandError),
}

/// Output emitted when the coroutine terminates its progression.
pub enum ImapMailboxStatusResult {
    Ok {
        context: ImapContext,
        items: Vec<StatusDataItem>,
    },
    WantsRead,
    WantsWrite(Vec<u8>),
    Err {
        context: ImapContext,
        err: ImapMailboxStatusError,
    },
}

/// I/O-free coroutine to send an IMAP STATUS command.
pub struct ImapMailboxStatus {
    send: SendImapCommand<CommandCodec>,
}

impl ImapMailboxStatus {
    /// Creates a new coroutine.
    pub fn new(
        mut context: ImapContext,
        mailbox: Mailbox<'static>,
        item_names: impl Into<Cow<'static, [StatusDataItemName]>>,
    ) -> Self {
        trace!("status IMAP mailbox: {mailbox:?}");

        let body = CommandBody::Status {
            mailbox,
            item_names: item_names.into(),
        };
        // SAFETY: tag is always valid
        let command = Command::new(context.generate_tag(), body).unwrap();
        Self {
            send: SendImapCommand::new(context, CommandCodec::new(), command),
        }
    }

    /// Advances the coroutine.
    pub fn resume(&mut self, arg: Option<&[u8]>) -> ImapMailboxStatusResult {
        let (context, data, tagged, bye) = match self.send.resume(arg) {
            SendImapCommandResult::WantsRead => return ImapMailboxStatusResult::WantsRead,
            SendImapCommandResult::WantsWrite(bytes) => {
                return ImapMailboxStatusResult::WantsWrite(bytes);
            }
            SendImapCommandResult::Ok {
                context,
                data,
                tagged,
                bye,
                ..
            } => (context, data, tagged, bye),
            SendImapCommandResult::Err { context, err } => {
                return ImapMailboxStatusResult::Err {
                    context,
                    err: err.into(),
                };
            }
        };

        if let Some(bye) = bye {
            let err = ImapMailboxStatusError::Bye(bye.text.to_string());
            return ImapMailboxStatusResult::Err { context, err };
        }

        let Some(Tagged { body, .. }) = tagged else {
            let err = ImapMailboxStatusError::MissingTagged;
            return ImapMailboxStatusResult::Err { context, err };
        };

        let mut items = Vec::new();

        for data in data {
            if let Data::Status {
                mailbox: _,
                items: status_items,
            } = data
            {
                items.extend(status_items.into_owned());
            }
        }

        match body.kind {
            StatusKind::Ok => ImapMailboxStatusResult::Ok { context, items },
            StatusKind::No => ImapMailboxStatusResult::Err {
                context,
                err: ImapMailboxStatusError::No(body.text.to_string()),
            },
            StatusKind::Bad => ImapMailboxStatusResult::Err {
                context,
                err: ImapMailboxStatusError::Bad(body.text.to_string()),
            },
        }
    }
}
