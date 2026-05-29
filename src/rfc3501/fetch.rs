//! I/O-free coroutine to send an IMAP FETCH command.

use core::num::NonZeroU32;

use alloc::{collections::BTreeMap, string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        command::{Command, CommandBody},
        core::{TagGenerator, Vec1},
        fetch::{MacroOrMessageDataItemNames, MessageDataItem},
        response::{Data, StatusKind, Tagged},
        sequence::{SeqOrUid, SequenceSet},
    },
};
use thiserror::Error;

use crate::coroutine::{ImapCoroutine, ImapCoroutineState};
use crate::send::*;

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum ImapMessageFetchError {
    #[error("IMAP FETCH NO error: {0}")]
    No(String),
    #[error("IMAP FETCH BAD error: {0}")]
    Bad(String),
    #[error("IMAP FETCH BYE error: {0}")]
    Bye(String),

    #[error("No IMAP FETCH tagged response returned by the server")]
    MissingTagged,
    #[error("No IMAP FETCH data returned by the server")]
    MissingData,

    #[error("Send IMAP FETCH command error")]
    Send(#[from] SendImapCommandError),
}

/// I/O-free coroutine to send an IMAP FETCH command.
pub struct ImapMessageFetch {
    pub(crate) send: SendImapCommand<CommandCodec>,
}

impl ImapMessageFetch {
    /// Creates a new coroutine.
    pub fn new(
        sequence_set: SequenceSet,
        macro_or_item_names: MacroOrMessageDataItemNames<'static>,
        uid: bool,
    ) -> Self {
        let body = CommandBody::Fetch {
            modifiers: Default::default(),
            sequence_set,
            macro_or_item_names,
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

impl ImapCoroutine for ImapMessageFetch {
    type Output = BTreeMap<NonZeroU32, Vec1<MessageDataItem<'static>>>;
    type Error = ImapMessageFetchError;

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
            return ImapCoroutineState::Err(ImapMessageFetchError::Bye(bye.text.to_string()));
        }

        let Some(Tagged { body, .. }) = tagged else {
            return ImapCoroutineState::Err(ImapMessageFetchError::MissingTagged);
        };

        let mut output: BTreeMap<NonZeroU32, Vec<MessageDataItem<'static>>> = BTreeMap::new();
        for data in data {
            if let Data::Fetch { seq, items } = data {
                output.entry(seq).or_default().extend(items.into_iter());
            }
        }

        match body.kind {
            StatusKind::Ok => ImapCoroutineState::Done(
                output
                    .into_iter()
                    .map(|(key, val)| (key, Vec1::unvalidated(val)))
                    .collect(),
            ),
            StatusKind::No => {
                ImapCoroutineState::Err(ImapMessageFetchError::No(body.text.to_string()))
            }
            StatusKind::Bad => {
                ImapCoroutineState::Err(ImapMessageFetchError::Bad(body.text.to_string()))
            }
        }
    }
}

/// I/O-free coroutine to send an IMAP FETCH command for a single message.
pub struct ImapMessageFetchFirst {
    send: SendImapCommand<CommandCodec>,
}

impl ImapMessageFetchFirst {
    /// Creates a new coroutine.
    pub fn new(
        id: NonZeroU32,
        macro_or_item_names: MacroOrMessageDataItemNames<'static>,
        uid: bool,
    ) -> Self {
        let body = CommandBody::Fetch {
            modifiers: Default::default(),
            sequence_set: SequenceSet::from(SeqOrUid::from(id)),
            macro_or_item_names,
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

impl ImapCoroutine for ImapMessageFetchFirst {
    type Output = Vec1<MessageDataItem<'static>>;
    type Error = ImapMessageFetchError;

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
            return ImapCoroutineState::Err(ImapMessageFetchError::Bye(bye.text.to_string()));
        }

        let Some(Tagged { body, .. }) = tagged else {
            return ImapCoroutineState::Err(ImapMessageFetchError::MissingTagged);
        };

        let mut output = None;
        for data in data {
            if let Data::Fetch { items, .. } = data {
                output = Some(items);
            }
        }

        match body.kind {
            StatusKind::Ok => match output {
                Some(items) => ImapCoroutineState::Done(items),
                None => ImapCoroutineState::Err(ImapMessageFetchError::MissingData),
            },
            StatusKind::No => {
                ImapCoroutineState::Err(ImapMessageFetchError::No(body.text.to_string()))
            }
            StatusKind::Bad => {
                ImapCoroutineState::Err(ImapMessageFetchError::Bad(body.text.to_string()))
            }
        }
    }
}
