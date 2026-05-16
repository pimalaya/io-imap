//! I/O-free coroutine to send an IMAP STORE command.

use core::num::NonZeroU32;

use alloc::{collections::BTreeMap, string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    imap_types::{
        command::{Command, CommandBody},
        core::Vec1,
        fetch::MessageDataItem,
        flag::{Flag, StoreResponse, StoreType},
        response::{Data, StatusKind, Tagged},
        sequence::SequenceSet,
    },
};
use thiserror::Error;

use crate::{context::ImapContext, send::*};

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

/// Output emitted when the coroutine terminates its progression.
pub enum ImapMessageStoreResult {
    Ok {
        context: ImapContext,
        data: BTreeMap<NonZeroU32, Vec1<MessageDataItem<'static>>>,
    },
    WantsRead,
    WantsWrite(Vec<u8>),
    Err {
        context: ImapContext,
        err: ImapMessageStoreError,
    },
}

/// I/O-free coroutine to send an IMAP STORE command.
pub struct ImapMessageStore {
    send: SendImapCommand<CommandCodec>,
}

impl ImapMessageStore {
    /// Creates a new coroutine.
    pub fn new(
        mut context: ImapContext,
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
        // SAFETY: tag is always valid
        let command = Command::new(context.generate_tag(), body).unwrap();
        Self {
            send: SendImapCommand::new(context, CommandCodec::new(), command),
        }
    }

    /// Advances the coroutine.
    pub fn resume(&mut self, arg: Option<&[u8]>) -> ImapMessageStoreResult {
        let (context, resp_data, tagged, bye) = match self.send.resume(arg) {
            SendImapCommandResult::WantsRead => return ImapMessageStoreResult::WantsRead,
            SendImapCommandResult::WantsWrite(bytes) => {
                return ImapMessageStoreResult::WantsWrite(bytes);
            }
            SendImapCommandResult::Ok {
                context,
                data,
                tagged,
                bye,
                ..
            } => (context, data, tagged, bye),
            SendImapCommandResult::Err { context, err } => {
                return ImapMessageStoreResult::Err {
                    context,
                    err: err.into(),
                };
            }
        };

        if let Some(bye) = bye {
            let err = ImapMessageStoreError::Bye(bye.text.to_string());
            return ImapMessageStoreResult::Err { context, err };
        }

        let Some(Tagged { body, .. }) = tagged else {
            let err = ImapMessageStoreError::MissingTagged;
            return ImapMessageStoreResult::Err { context, err };
        };

        let mut data: BTreeMap<NonZeroU32, Vec1<MessageDataItem<'static>>> = BTreeMap::new();

        for res_data in resp_data {
            if let Data::Fetch { seq, items } = res_data {
                data.insert(seq, items);
            }
        }

        match body.kind {
            StatusKind::Ok => ImapMessageStoreResult::Ok { context, data },
            StatusKind::No => ImapMessageStoreResult::Err {
                context,
                err: ImapMessageStoreError::No(body.text.to_string()),
            },
            StatusKind::Bad => ImapMessageStoreResult::Err {
                context,
                err: ImapMessageStoreError::Bad(body.text.to_string()),
            },
        }
    }
}

/// Output emitted when the silent store coroutine terminates.
pub enum ImapMessageStoreSilentResult {
    Ok {
        context: ImapContext,
    },
    WantsRead,
    WantsWrite(Vec<u8>),
    Err {
        context: ImapContext,
        err: ImapMessageStoreError,
    },
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
        mut context: ImapContext,
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
        // SAFETY: tag is always valid
        let command = Command::new(context.generate_tag(), body).unwrap();
        Self {
            send: SendImapCommand::new(context, CommandCodec::new(), command),
        }
    }

    /// Advances the coroutine.
    pub fn resume(&mut self, arg: Option<&[u8]>) -> ImapMessageStoreSilentResult {
        let (context, tagged, bye) = match self.send.resume(arg) {
            SendImapCommandResult::WantsRead => return ImapMessageStoreSilentResult::WantsRead,
            SendImapCommandResult::WantsWrite(bytes) => {
                return ImapMessageStoreSilentResult::WantsWrite(bytes);
            }
            SendImapCommandResult::Ok {
                context,
                tagged,
                bye,
                ..
            } => (context, tagged, bye),
            SendImapCommandResult::Err { context, err } => {
                return ImapMessageStoreSilentResult::Err {
                    context,
                    err: err.into(),
                };
            }
        };

        if let Some(bye) = bye {
            let err = ImapMessageStoreError::Bye(bye.text.to_string());
            return ImapMessageStoreSilentResult::Err { context, err };
        }

        let Some(Tagged { body, .. }) = tagged else {
            let err = ImapMessageStoreError::MissingTagged;
            return ImapMessageStoreSilentResult::Err { context, err };
        };

        match body.kind {
            StatusKind::Ok => ImapMessageStoreSilentResult::Ok { context },
            StatusKind::No => ImapMessageStoreSilentResult::Err {
                context,
                err: ImapMessageStoreError::No(body.text.to_string()),
            },
            StatusKind::Bad => ImapMessageStoreSilentResult::Err {
                context,
                err: ImapMessageStoreError::Bad(body.text.to_string()),
            },
        }
    }
}
