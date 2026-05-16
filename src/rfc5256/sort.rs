//! I/O-free coroutine to send an IMAP SORT command.

use core::num::NonZeroU32;

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    imap_types::{
        command::{Command, CommandBody},
        core::{Charset, Vec1},
        extensions::sort::SortCriterion,
        response::{Data, StatusKind, Tagged},
        search::SearchKey,
    },
};
use thiserror::Error;

use crate::{context::ImapContext, send::*};

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum ImapMailboxSortError {
    #[error("IMAP SORT NO error: {0}")]
    No(String),
    #[error("IMAP SORT BAD error: {0}")]
    Bad(String),
    #[error("IMAP SORT BYE error: {0}")]
    Bye(String),

    #[error("No IMAP SORT tagged response returned by the server")]
    MissingTagged,
    #[error("No IMAP SORT data returned by the server")]
    MissingData,

    #[error("Send IMAP SORT command error")]
    Send(#[from] SendImapCommandError),
}

/// Output emitted when the coroutine terminates its progression.
pub enum ImapMailboxSortResult {
    Ok {
        context: ImapContext,
        ids: Vec<NonZeroU32>,
    },
    WantsRead,
    WantsWrite(Vec<u8>),
    Err {
        context: ImapContext,
        err: ImapMailboxSortError,
    },
}

/// I/O-free coroutine to send an IMAP SORT command.
pub struct ImapMailboxSort {
    send: SendImapCommand<CommandCodec>,
}

impl ImapMailboxSort {
    /// Creates a new coroutine.
    pub fn new(
        mut context: ImapContext,
        sort_criteria: Vec1<SortCriterion>,
        search_criteria: Vec1<SearchKey<'static>>,
        uid: bool,
    ) -> Self {
        let body = CommandBody::Sort {
            sort_criteria,
            charset: Charset::try_from("UTF-8").unwrap(),
            search_criteria,
            uid,
        };
        // SAFETY: tag is always valid
        let command = Command::new(context.generate_tag(), body).unwrap();
        Self {
            send: SendImapCommand::new(context, CommandCodec::new(), command),
        }
    }

    /// Advances the coroutine.
    pub fn resume(&mut self, arg: Option<&[u8]>) -> ImapMailboxSortResult {
        let (context, data, tagged, bye) = match self.send.resume(arg) {
            SendImapCommandResult::WantsRead => return ImapMailboxSortResult::WantsRead,
            SendImapCommandResult::WantsWrite(bytes) => {
                return ImapMailboxSortResult::WantsWrite(bytes);
            }
            SendImapCommandResult::Ok {
                context,
                data,
                tagged,
                bye,
                ..
            } => (context, data, tagged, bye),
            SendImapCommandResult::Err { context, err } => {
                return ImapMailboxSortResult::Err {
                    context,
                    err: err.into(),
                };
            }
        };

        if let Some(bye) = bye {
            let err = ImapMailboxSortError::Bye(bye.text.to_string());
            return ImapMailboxSortResult::Err { context, err };
        }

        let Some(Tagged { body, .. }) = tagged else {
            let err = ImapMailboxSortError::MissingTagged;
            return ImapMailboxSortResult::Err { context, err };
        };

        let mut ids = None;

        for data in data {
            if let Data::Sort(sort_ids, _) = data {
                ids = Some(sort_ids);
            }
        }

        match body.kind {
            StatusKind::Ok => match ids {
                Some(ids) => ImapMailboxSortResult::Ok { context, ids },
                None => ImapMailboxSortResult::Err {
                    context,
                    err: ImapMailboxSortError::MissingData,
                },
            },
            StatusKind::No => ImapMailboxSortResult::Err {
                context,
                err: ImapMailboxSortError::No(body.text.to_string()),
            },
            StatusKind::Bad => ImapMailboxSortResult::Err {
                context,
                err: ImapMailboxSortError::Bad(body.text.to_string()),
            },
        }
    }
}
