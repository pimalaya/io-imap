//! I/O-free coroutine to send an IMAP SEARCH command.

use core::num::NonZeroU32;

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    imap_types::{
        command::{Command, CommandBody},
        core::Vec1,
        response::{Data, StatusKind, Tagged},
        search::SearchKey,
    },
};
use thiserror::Error;

use crate::{context::ImapContext, send::*};

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum ImapMessageSearchError {
    #[error("IMAP SEARCH NO error: {0}")]
    No(String),
    #[error("IMAP SEARCH BAD error: {0}")]
    Bad(String),
    #[error("IMAP SEARCH BYE error: {0}")]
    Bye(String),

    #[error("No IMAP SEARCH tagged response returned by the server")]
    MissingTagged,

    #[error("Send IMAP SEARCH command error")]
    Send(#[from] SendImapCommandError),
}

/// Output emitted when the coroutine terminates its progression.
pub enum ImapMessageSearchResult {
    Ok {
        context: ImapContext,
        ids: Vec<NonZeroU32>,
    },
    WantsRead,
    WantsWrite(Vec<u8>),
    Err {
        context: ImapContext,
        err: ImapMessageSearchError,
    },
}

/// I/O-free coroutine to send an IMAP SEARCH command.
pub struct ImapMessageSearch {
    send: SendImapCommand<CommandCodec>,
}

impl ImapMessageSearch {
    /// Creates a new coroutine.
    pub fn new(mut context: ImapContext, criteria: Vec1<SearchKey<'static>>, uid: bool) -> Self {
        let body = CommandBody::Search {
            charset: None,
            criteria,
            uid,
        };
        // SAFETY: tag is always valid
        let command = Command::new(context.generate_tag(), body).unwrap();
        Self {
            send: SendImapCommand::new(context, CommandCodec::new(), command),
        }
    }

    /// Advances the coroutine.
    pub fn resume(&mut self, arg: Option<&[u8]>) -> ImapMessageSearchResult {
        let (context, data, tagged, bye) = match self.send.resume(arg) {
            SendImapCommandResult::WantsRead => return ImapMessageSearchResult::WantsRead,
            SendImapCommandResult::WantsWrite(bytes) => {
                return ImapMessageSearchResult::WantsWrite(bytes);
            }
            SendImapCommandResult::Ok {
                context,
                data,
                tagged,
                bye,
                ..
            } => (context, data, tagged, bye),
            SendImapCommandResult::Err { context, err } => {
                return ImapMessageSearchResult::Err {
                    context,
                    err: err.into(),
                };
            }
        };

        if let Some(bye) = bye {
            let err = ImapMessageSearchError::Bye(bye.text.to_string());
            return ImapMessageSearchResult::Err { context, err };
        }

        let Some(Tagged { body, .. }) = tagged else {
            let err = ImapMessageSearchError::MissingTagged;
            return ImapMessageSearchResult::Err { context, err };
        };

        let mut ids = Vec::new();

        for data in data {
            if let Data::Search(search_ids, _) = data {
                ids = search_ids;
            }
        }

        match body.kind {
            StatusKind::Ok => ImapMessageSearchResult::Ok { context, ids },
            StatusKind::No => ImapMessageSearchResult::Err {
                context,
                err: ImapMessageSearchError::No(body.text.to_string()),
            },
            StatusKind::Bad => ImapMessageSearchResult::Err {
                context,
                err: ImapMessageSearchError::Bad(body.text.to_string()),
            },
        }
    }
}
