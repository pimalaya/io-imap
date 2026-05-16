//! I/O-free coroutine to send an IMAP SELECT or EXAMINE command.

use core::num::NonZeroU32;

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    imap_types::{
        command::{Command, CommandBody},
        flag::{Flag, FlagPerm},
        mailbox::Mailbox,
        response::{Code, Data, StatusBody, StatusKind, Tagged},
    },
};
use thiserror::Error;

use crate::{
    context::{ImapContext, ImapCurrentMailboxState},
    send::*,
};

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum ImapMailboxSelectError {
    #[error("IMAP SELECT NO error: {0}")]
    No(String),
    #[error("IMAP SELECT BAD error: {0}")]
    Bad(String),
    #[error("IMAP SELECT BYE error: {0}")]
    Bye(String),

    #[error("No IMAP SELECT tagged response returned by the server")]
    MissingTagged,

    #[error("Send IMAP SELECT command error")]
    Send(#[from] SendImapCommandError),
}

/// Data collected from a SELECT or EXAMINE response.
#[derive(Clone, Debug, Default)]
pub struct SelectData {
    pub flags: Option<Vec<Flag<'static>>>,
    pub exists: Option<u32>,
    pub recent: Option<u32>,
    pub unseen: Option<NonZeroU32>,
    pub permanent_flags: Option<Vec<FlagPerm<'static>>>,
    pub uid_next: Option<NonZeroU32>,
    pub uid_validity: Option<NonZeroU32>,
}

/// Output emitted when the coroutine terminates its progression.
pub enum ImapMailboxSelectResult {
    Ok {
        context: ImapContext,
        data: SelectData,
    },
    WantsRead,
    WantsWrite(Vec<u8>),
    Err {
        context: ImapContext,
        err: ImapMailboxSelectError,
    },
}

/// I/O-free coroutine to send an IMAP SELECT or EXAMINE command.
pub struct ImapMailboxSelect {
    select_state: ImapCurrentMailboxState,
    send: SendImapCommand<CommandCodec>,
}

impl ImapMailboxSelect {
    /// Creates a new coroutine for SELECT.
    pub fn new(mut context: ImapContext, mailbox: Mailbox<'static>) -> Self {
        let select_state = ImapCurrentMailboxState::Selected(mailbox.clone());

        let body = CommandBody::Select {
            mailbox,
            parameters: Default::default(),
        };

        // SAFETY: tag is always valid
        let command = Command::new(context.generate_tag(), body).unwrap();

        Self {
            select_state,
            send: SendImapCommand::new(context, CommandCodec::new(), command),
        }
    }

    /// Creates a new coroutine for EXAMINE (read-only).
    pub fn read_only(mut context: ImapContext, mailbox: Mailbox<'static>) -> Self {
        let select_state = ImapCurrentMailboxState::SelectedReadOnly(mailbox.clone());

        let body = CommandBody::Examine {
            mailbox,
            parameters: Default::default(),
        };

        // SAFETY: tag is always valid
        let command = Command::new(context.generate_tag(), body).unwrap();

        Self {
            select_state,
            send: SendImapCommand::new(context, CommandCodec::new(), command),
        }
    }

    /// Advances the coroutine.
    pub fn resume(&mut self, arg: Option<&[u8]>) -> ImapMailboxSelectResult {
        let (mut context, data, untagged, tagged, bye) = match self.send.resume(arg) {
            SendImapCommandResult::WantsRead => return ImapMailboxSelectResult::WantsRead,
            SendImapCommandResult::WantsWrite(bytes) => {
                return ImapMailboxSelectResult::WantsWrite(bytes);
            }
            SendImapCommandResult::Ok {
                context,
                data,
                untagged,
                tagged,
                bye,
                ..
            } => (context, data, untagged, tagged, bye),
            SendImapCommandResult::Err { context, err } => {
                return ImapMailboxSelectResult::Err {
                    context,
                    err: err.into(),
                };
            }
        };

        if let Some(bye) = bye {
            let err = ImapMailboxSelectError::Bye(bye.text.to_string());
            return ImapMailboxSelectResult::Err { context, err };
        }

        let Some(Tagged { body, .. }) = tagged else {
            let err = ImapMailboxSelectError::MissingTagged;
            return ImapMailboxSelectResult::Err { context, err };
        };

        let mut output = SelectData::default();

        for data in data {
            match data {
                Data::Flags(flags) => output.flags = Some(flags),
                Data::Exists(count) => output.exists = Some(count),
                Data::Recent(count) => output.recent = Some(count),
                _ => {}
            }
        }

        for StatusBody { kind, code, .. } in untagged {
            if let StatusKind::Ok = kind {
                match code {
                    Some(Code::Unseen(seq)) => output.unseen = Some(seq),
                    Some(Code::PermanentFlags(flags)) => output.permanent_flags = Some(flags),
                    Some(Code::UidNext(uid)) => output.uid_next = Some(uid),
                    Some(Code::UidValidity(uid)) => output.uid_validity = Some(uid),
                    _ => {}
                }
            }
        }

        match body.kind {
            StatusKind::Ok => {
                context.mailbox = self.select_state.clone();
                context.flags = output
                    .flags
                    .clone()
                    .unwrap_or_default()
                    .into_iter()
                    .collect();
                context.permanent_flags = output
                    .permanent_flags
                    .clone()
                    .unwrap_or_default()
                    .into_iter()
                    .collect();
                ImapMailboxSelectResult::Ok {
                    context,
                    data: output,
                }
            }
            StatusKind::No => ImapMailboxSelectResult::Err {
                context,
                err: ImapMailboxSelectError::No(body.text.to_string()),
            },
            StatusKind::Bad => ImapMailboxSelectResult::Err {
                context,
                err: ImapMailboxSelectError::Bad(body.text.to_string()),
            },
        }
    }
}
