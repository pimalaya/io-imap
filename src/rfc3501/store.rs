//! I/O-free coroutine to send an IMAP STORE command.

use core::num::NonZeroU32;

use alloc::{collections::BTreeMap, string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        command::{Command, CommandBody},
        core::{TagGenerator, Vec1},
        fetch::MessageDataItem,
        flag::{Flag, StoreResponse, StoreType},
        response::{Data, StatusKind, Tagged},
        sequence::SequenceSet,
    },
};
use thiserror::Error;

use crate::coroutine::*;
use crate::send::*;

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum ImapMessageStoreError {
    #[error("IMAP STORE NO error: {0}")]
    No(String),
    #[error("IMAP STORE BAD error: {0}")]
    Bad(String),
    #[error("IMAP STORE BYE error: {0}")]
    Bye(String),

    #[error("No IMAP STORE tagged response returned by the server")]
    MissingTagged,

    #[error("Send IMAP STORE command error")]
    Send(#[from] SendImapCommandError),
}

/// I/O-free coroutine to send an IMAP STORE command.
pub struct ImapMessageStore {
    send: SendImapCommand<CommandCodec>,
}

impl ImapMessageStore {
    /// Creates a new coroutine.
    pub fn new(
        sequence_set: SequenceSet,
        kind: StoreType,
        flags: Vec<Flag<'static>>,
        uid: bool,
    ) -> Self {
        let body = CommandBody::Store {
            modifiers: Default::default(),
            sequence_set,
            kind,
            response: StoreResponse::Answer,
            flags,
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

impl ImapCoroutine for ImapMessageStore {
    type Yield = ImapYield;
    type Return =
        Result<BTreeMap<NonZeroU32, Vec1<MessageDataItem<'static>>>, ImapMessageStoreError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        let (resp_data, tagged, bye) = match self.send.resume(fragmentizer, arg) {
            SendImapCommandResult::WantsRead => {
                return ImapCoroutineState::Yielded(ImapYield::WantsRead);
            }
            SendImapCommandResult::WantsWrite(bytes) => {
                return ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes));
            }
            SendImapCommandResult::Ok {
                data, tagged, bye, ..
            } => (data, tagged, bye),
            SendImapCommandResult::Err(err) => {
                return ImapCoroutineState::Complete(Err(err.into()));
            }
        };

        if let Some(bye) = bye {
            return ImapCoroutineState::Complete(Err(ImapMessageStoreError::Bye(
                bye.text.to_string(),
            )));
        }

        let Some(Tagged { body, .. }) = tagged else {
            return ImapCoroutineState::Complete(Err(ImapMessageStoreError::MissingTagged));
        };

        let mut data: BTreeMap<NonZeroU32, Vec1<MessageDataItem<'static>>> = BTreeMap::new();
        for res_data in resp_data {
            if let Data::Fetch { seq, items } = res_data {
                data.insert(seq, items);
            }
        }

        match body.kind {
            StatusKind::Ok => ImapCoroutineState::Complete(Ok(data)),
            StatusKind::No => {
                ImapCoroutineState::Complete(Err(ImapMessageStoreError::No(body.text.to_string())))
            }
            StatusKind::Bad => {
                ImapCoroutineState::Complete(Err(ImapMessageStoreError::Bad(body.text.to_string())))
            }
        }
    }
}

/// I/O-free coroutine to send a silent IMAP STORE command.
///
/// Same as [`ImapMessageStore`], but instructs the server to not send
/// back the updated values.
pub struct ImapMessageStoreSilent {
    send: SendImapCommand<CommandCodec>,
}

impl ImapMessageStoreSilent {
    /// Creates a new coroutine.
    pub fn new(
        sequence_set: SequenceSet,
        kind: StoreType,
        flags: Vec<Flag<'static>>,
        uid: bool,
    ) -> Self {
        let body = CommandBody::Store {
            modifiers: Default::default(),
            sequence_set,
            kind,
            response: StoreResponse::Silent,
            flags,
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

impl ImapCoroutine for ImapMessageStoreSilent {
    type Yield = ImapYield;
    type Return = Result<(), ImapMessageStoreError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        let (tagged, bye) = match self.send.resume(fragmentizer, arg) {
            SendImapCommandResult::WantsRead => {
                return ImapCoroutineState::Yielded(ImapYield::WantsRead);
            }
            SendImapCommandResult::WantsWrite(bytes) => {
                return ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes));
            }
            SendImapCommandResult::Ok { tagged, bye, .. } => (tagged, bye),
            SendImapCommandResult::Err(err) => {
                return ImapCoroutineState::Complete(Err(err.into()));
            }
        };

        if let Some(bye) = bye {
            return ImapCoroutineState::Complete(Err(ImapMessageStoreError::Bye(
                bye.text.to_string(),
            )));
        }

        let Some(Tagged { body, .. }) = tagged else {
            return ImapCoroutineState::Complete(Err(ImapMessageStoreError::MissingTagged));
        };

        match body.kind {
            StatusKind::Ok => ImapCoroutineState::Complete(Ok(())),
            StatusKind::No => {
                ImapCoroutineState::Complete(Err(ImapMessageStoreError::No(body.text.to_string())))
            }
            StatusKind::Bad => {
                ImapCoroutineState::Complete(Err(ImapMessageStoreError::Bad(body.text.to_string())))
            }
        }
    }
}
