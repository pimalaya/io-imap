//! I/O-free coroutine to send an IMAP FETCH command.

use core::num::NonZeroU32;

use alloc::{collections::BTreeMap, string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    imap_types::{
        command::{Command, CommandBody},
        core::Vec1,
        fetch::{MacroOrMessageDataItemNames, MessageDataItem},
        response::{Data, StatusKind, Tagged},
        sequence::{SeqOrUid, SequenceSet},
    },
};
use thiserror::Error;

use crate::{context::ImapContext, send::*};

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

/// Output emitted when the coroutine terminates its progression.
pub enum ImapMessageFetchResult {
    Ok {
        context: ImapContext,
        data: BTreeMap<NonZeroU32, Vec1<MessageDataItem<'static>>>,
    },
    WantsRead,
    WantsWrite(Vec<u8>),
    Err {
        context: ImapContext,
        err: ImapMessageFetchError,
    },
}

/// I/O-free coroutine to send an IMAP FETCH command.
pub struct ImapMessageFetch {
    send: SendImapCommand<CommandCodec>,
}

impl ImapMessageFetch {
    /// Creates a new coroutine.
    pub fn new(
        mut context: ImapContext,
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
        // SAFETY: tag is always valid
        let command = Command::new(context.generate_tag(), body).unwrap();
        Self {
            send: SendImapCommand::new(context, CommandCodec::new(), command),
        }
    }

    /// Advances the coroutine.
    pub fn resume(&mut self, arg: Option<&[u8]>) -> ImapMessageFetchResult {
        let (context, data, tagged, bye) = match self.send.resume(arg) {
            SendImapCommandResult::WantsRead => return ImapMessageFetchResult::WantsRead,
            SendImapCommandResult::WantsWrite(bytes) => {
                return ImapMessageFetchResult::WantsWrite(bytes);
            }
            SendImapCommandResult::Ok {
                context,
                data,
                tagged,
                bye,
                ..
            } => (context, data, tagged, bye),
            SendImapCommandResult::Err { context, err } => {
                return ImapMessageFetchResult::Err {
                    context,
                    err: err.into(),
                };
            }
        };

        if let Some(bye) = bye {
            let err = ImapMessageFetchError::Bye(bye.text.to_string());
            return ImapMessageFetchResult::Err { context, err };
        }

        let Some(Tagged { body, .. }) = tagged else {
            let err = ImapMessageFetchError::MissingTagged;
            return ImapMessageFetchResult::Err { context, err };
        };

        let mut output: BTreeMap<NonZeroU32, Vec<MessageDataItem<'static>>> = BTreeMap::new();

        for data in data {
            if let Data::Fetch { seq, items } = data {
                output.entry(seq).or_default().extend(items.into_iter());
            }
        }

        match body.kind {
            StatusKind::Ok => ImapMessageFetchResult::Ok {
                context,
                data: output
                    .into_iter()
                    .map(|(key, val)| (key, Vec1::unvalidated(val)))
                    .collect(),
            },
            StatusKind::No => ImapMessageFetchResult::Err {
                context,
                err: ImapMessageFetchError::No(body.text.to_string()),
            },
            StatusKind::Bad => ImapMessageFetchResult::Err {
                context,
                err: ImapMessageFetchError::Bad(body.text.to_string()),
            },
        }
    }
}

/// Output emitted when the coroutine terminates its progression.
pub enum ImapMessageFetchFirstResult {
    Ok {
        context: ImapContext,
        items: Vec1<MessageDataItem<'static>>,
    },
    WantsRead,
    WantsWrite(Vec<u8>),
    Err {
        context: ImapContext,
        err: ImapMessageFetchError,
    },
}

/// I/O-free coroutine to send an IMAP FETCH command for a single message.
pub struct ImapMessageFetchFirst {
    send: SendImapCommand<CommandCodec>,
}

impl ImapMessageFetchFirst {
    /// Creates a new coroutine.
    pub fn new(
        mut context: ImapContext,
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
        // SAFETY: tag is always valid
        let command = Command::new(context.generate_tag(), body).unwrap();
        Self {
            send: SendImapCommand::new(context, CommandCodec::new(), command),
        }
    }

    /// Advances the coroutine.
    pub fn resume(&mut self, arg: Option<&[u8]>) -> ImapMessageFetchFirstResult {
        let (context, data, tagged, bye) = match self.send.resume(arg) {
            SendImapCommandResult::WantsRead => return ImapMessageFetchFirstResult::WantsRead,
            SendImapCommandResult::WantsWrite(bytes) => {
                return ImapMessageFetchFirstResult::WantsWrite(bytes);
            }
            SendImapCommandResult::Ok {
                context,
                data,
                tagged,
                bye,
                ..
            } => (context, data, tagged, bye),
            SendImapCommandResult::Err { context, err } => {
                return ImapMessageFetchFirstResult::Err {
                    context,
                    err: err.into(),
                };
            }
        };

        if let Some(bye) = bye {
            let err = ImapMessageFetchError::Bye(bye.text.to_string());
            return ImapMessageFetchFirstResult::Err { context, err };
        }

        let Some(Tagged { body, .. }) = tagged else {
            let err = ImapMessageFetchError::MissingTagged;
            return ImapMessageFetchFirstResult::Err { context, err };
        };

        let mut output = None;

        for data in data {
            if let Data::Fetch { items, .. } = data {
                output = Some(items);
            }
        }

        match body.kind {
            StatusKind::Ok => match output {
                Some(items) => ImapMessageFetchFirstResult::Ok { context, items },
                None => ImapMessageFetchFirstResult::Err {
                    context,
                    err: ImapMessageFetchError::MissingData,
                },
            },
            StatusKind::No => ImapMessageFetchFirstResult::Err {
                context,
                err: ImapMessageFetchError::No(body.text.to_string()),
            },
            StatusKind::Bad => ImapMessageFetchFirstResult::Err {
                context,
                err: ImapMessageFetchError::Bad(body.text.to_string()),
            },
        }
    }
}
