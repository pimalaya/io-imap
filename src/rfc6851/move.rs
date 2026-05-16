//! I/O-free coroutine to send an IMAP MOVE command.

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    imap_types::{
        command::{Command, CommandBody},
        extensions::uidplus::{UidElement, UidSet},
        mailbox::Mailbox,
        response::{Code, StatusKind, Tagged},
        sequence::SequenceSet,
    },
};
use thiserror::Error;

use crate::{context::ImapContext, rfc3501::copy::ImapCopyUid, send::*};

/// Expand a `UidSet` into a sorted `Vec<u32>`.
fn uid_set_to_vec(uid_set: UidSet) -> Vec<u32> {
    let mut uids = Vec::new();

    for elem in uid_set.0 {
        match elem {
            UidElement::Single(uid) => uids.push(uid.get()),
            UidElement::Range(start, end) => {
                let (lo, hi) = if start <= end {
                    (start.get(), end.get())
                } else {
                    (end.get(), start.get())
                };
                for uid in lo..=hi {
                    uids.push(uid);
                }
            }
        }
    }

    uids.sort_unstable();
    uids
}

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum ImapMessageMoveError {
    #[error("IMAP MOVE NO error: {0}")]
    No(String),
    #[error("IMAP MOVE BAD error: {0}")]
    Bad(String),
    #[error("IMAP MOVE BYE error: {0}")]
    Bye(String),

    #[error("No IMAP MOVE tagged response returned by the server")]
    MissingTagged,

    #[error("Send IMAP MOVE command error")]
    Send(#[from] SendImapCommandError),
}

/// Output emitted when the coroutine terminates its progression.
pub enum ImapMessageMoveResult {
    Ok {
        context: ImapContext,
        copyuid: ImapCopyUid,
    },
    WantsRead,
    WantsWrite(Vec<u8>),
    Err {
        context: ImapContext,
        err: ImapMessageMoveError,
    },
}

/// I/O-free coroutine to send an IMAP MOVE command.
pub struct ImapMessageMove {
    send: SendImapCommand<CommandCodec>,
}

impl ImapMessageMove {
    /// Creates a new coroutine.
    pub fn new(
        mut context: ImapContext,
        sequence_set: SequenceSet,
        mailbox: Mailbox<'static>,
        uid: bool,
    ) -> Self {
        let body = CommandBody::Move {
            sequence_set,
            mailbox,
            uid,
        };
        // SAFETY: tag is always valid
        let command = Command::new(context.generate_tag(), body).unwrap();
        Self {
            send: SendImapCommand::new(context, CommandCodec::new(), command),
        }
    }

    /// Advances the coroutine.
    pub fn resume(&mut self, arg: Option<&[u8]>) -> ImapMessageMoveResult {
        let (context, tagged, bye) = match self.send.resume(arg) {
            SendImapCommandResult::WantsRead => return ImapMessageMoveResult::WantsRead,
            SendImapCommandResult::WantsWrite(bytes) => {
                return ImapMessageMoveResult::WantsWrite(bytes);
            }
            SendImapCommandResult::Ok {
                context,
                tagged,
                bye,
                ..
            } => (context, tagged, bye),
            SendImapCommandResult::Err { context, err } => {
                return ImapMessageMoveResult::Err {
                    context,
                    err: err.into(),
                };
            }
        };

        if let Some(bye) = bye {
            let err = ImapMessageMoveError::Bye(bye.text.to_string());
            return ImapMessageMoveResult::Err { context, err };
        }

        let Some(Tagged { body, .. }) = tagged else {
            let err = ImapMessageMoveError::MissingTagged;
            return ImapMessageMoveResult::Err { context, err };
        };

        match body.kind {
            StatusKind::Ok => {
                let copyuid = if let Some(Code::CopyUid {
                    uid_validity,
                    source,
                    destination,
                }) = body.code
                {
                    Some((
                        uid_validity.get(),
                        uid_set_to_vec(source),
                        uid_set_to_vec(destination),
                    ))
                } else {
                    None
                };
                ImapMessageMoveResult::Ok { context, copyuid }
            }
            StatusKind::No => ImapMessageMoveResult::Err {
                context,
                err: ImapMessageMoveError::No(body.text.to_string()),
            },
            StatusKind::Bad => ImapMessageMoveResult::Err {
                context,
                err: ImapMessageMoveError::Bad(body.text.to_string()),
            },
        }
    }
}
