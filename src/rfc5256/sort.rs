//! I/O-free coroutine to send an IMAP SORT command.

use core::num::NonZeroU32;

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        command::{Command, CommandBody},
        core::{Charset, TagGenerator, Vec1},
        extensions::sort::SortCriterion,
        response::{Data, StatusKind, Tagged},
        search::SearchKey,
    },
};
use thiserror::Error;

use crate::coroutine::{ImapCoroutine, ImapCoroutineState};
use crate::send::*;

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

/// I/O-free coroutine to send an IMAP SORT command.
pub struct ImapMailboxSort {
    send: SendImapCommand<CommandCodec>,
}

impl ImapMailboxSort {
    /// Creates a new coroutine.
    pub fn new(
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
        let mut tag = TagGenerator::new();
        // SAFETY: tag is always valid
        let command = Command::new(tag.generate(), body).unwrap();
        Self {
            send: SendImapCommand::new(CommandCodec::new(), command),
        }
    }
}

impl ImapCoroutine for ImapMailboxSort {
    type Output = Vec<NonZeroU32>;
    type Error = ImapMailboxSortError;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Output, Self::Error> {
        let (data, tagged, bye) = match self.send.resume(fragmentizer, arg) {
            SendImapCommandResult::WantsRead => return ImapCoroutineState::WantsRead,
            SendImapCommandResult::WantsWrite(bytes) => {
                return ImapCoroutineState::WantsWrite(bytes);
            }
            SendImapCommandResult::Ok {
                data, tagged, bye, ..
            } => (data, tagged, bye),
            SendImapCommandResult::Err(err) => return ImapCoroutineState::Err(err.into()),
        };

        if let Some(bye) = bye {
            return ImapCoroutineState::Err(ImapMailboxSortError::Bye(bye.text.to_string()));
        }

        let Some(Tagged { body, .. }) = tagged else {
            return ImapCoroutineState::Err(ImapMailboxSortError::MissingTagged);
        };

        let mut ids = None;
        for data in data {
            if let Data::Sort(sort_ids, _) = data {
                ids = Some(sort_ids);
            }
        }

        match body.kind {
            StatusKind::Ok => match ids {
                Some(ids) => ImapCoroutineState::Done(ids),
                None => ImapCoroutineState::Err(ImapMailboxSortError::MissingData),
            },
            StatusKind::No => {
                ImapCoroutineState::Err(ImapMailboxSortError::No(body.text.to_string()))
            }
            StatusKind::Bad => {
                ImapCoroutineState::Err(ImapMailboxSortError::Bad(body.text.to_string()))
            }
        }
    }
}
