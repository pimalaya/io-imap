//! I/O-free coroutine to send an IMAP SEARCH command.

use core::num::NonZeroU32;

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        command::{Command, CommandBody},
        core::{TagGenerator, Vec1},
        response::{Data, StatusKind, Tagged},
        search::SearchKey,
    },
};
use thiserror::Error;

use crate::coroutine::{ImapCoroutine, ImapCoroutineState};
use crate::send::*;

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

/// I/O-free coroutine to send an IMAP SEARCH command.
pub struct ImapMessageSearch {
    send: SendImapCommand<CommandCodec>,
}

impl ImapMessageSearch {
    /// Creates a new coroutine.
    pub fn new(criteria: Vec1<SearchKey<'static>>, uid: bool) -> Self {
        let body = CommandBody::Search {
            charset: None,
            criteria,
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

impl ImapCoroutine for ImapMessageSearch {
    type Output = Vec<NonZeroU32>;
    type Error = ImapMessageSearchError;

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
            return ImapCoroutineState::Err(ImapMessageSearchError::Bye(bye.text.to_string()));
        }

        let Some(Tagged { body, .. }) = tagged else {
            return ImapCoroutineState::Err(ImapMessageSearchError::MissingTagged);
        };

        let mut ids = Vec::new();
        for data in data {
            if let Data::Search(search_ids, _) = data {
                ids = search_ids;
            }
        }

        match body.kind {
            StatusKind::Ok => ImapCoroutineState::Done(ids),
            StatusKind::No => {
                ImapCoroutineState::Err(ImapMessageSearchError::No(body.text.to_string()))
            }
            StatusKind::Bad => {
                ImapCoroutineState::Err(ImapMessageSearchError::Bad(body.text.to_string()))
            }
        }
    }
}
