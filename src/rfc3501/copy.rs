//! I/O-free coroutine to send an IMAP COPY command.

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

use crate::{context::ImapContext, send::*};

/// Output of the IMAP `COPY` (and `MOVE`) command: the
/// `[COPYUID uidvalidity src-uids dst-uids]` response code (RFC 4315) if the
/// server returned one, decoded as `(uidvalidity, source UIDs,
/// destination UIDs)`.
pub type ImapCopyUid = Option<(u32, Vec<u32>, Vec<u32>)>;

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
pub enum ImapMessageCopyError {
    #[error("IMAP COPY NO error: {0}")]
    No(String),
    #[error("IMAP COPY BAD error: {0}")]
    Bad(String),
    #[error("IMAP COPY BYE error: {0}")]
    Bye(String),

    #[error("No IMAP COPY tagged response returned by the server")]
    MissingTagged,

    #[error("Send IMAP COPY command error")]
    Send(#[from] SendImapCommandError),
}

/// Output emitted when the coroutine terminates its progression.
pub enum ImapMessageCopyResult {
    Ok {
        context: ImapContext,
        copyuid: ImapCopyUid,
    },
    WantsRead,
    WantsWrite(Vec<u8>),
    Err {
        context: ImapContext,
        err: ImapMessageCopyError,
    },
}

/// I/O-free coroutine to send an IMAP COPY command.
pub struct ImapMessageCopy {
    send: SendImapCommand<CommandCodec>,
}

impl ImapMessageCopy {
    /// Creates a new coroutine.
    pub fn new(
        mut context: ImapContext,
        sequence_set: SequenceSet,
        mailbox: Mailbox<'static>,
        uid: bool,
    ) -> Self {
        let body = CommandBody::Copy {
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
    pub fn resume(&mut self, arg: Option<&[u8]>) -> ImapMessageCopyResult {
        let (context, tagged, bye) = match self.send.resume(arg) {
            SendImapCommandResult::WantsRead => return ImapMessageCopyResult::WantsRead,
            SendImapCommandResult::WantsWrite(bytes) => {
                return ImapMessageCopyResult::WantsWrite(bytes);
            }
            SendImapCommandResult::Ok {
                context,
                tagged,
                bye,
                ..
            } => (context, tagged, bye),
            SendImapCommandResult::Err { context, err } => {
                return ImapMessageCopyResult::Err {
                    context,
                    err: err.into(),
                };
            }
        };

        if let Some(bye) = bye {
            let err = ImapMessageCopyError::Bye(bye.text.to_string());
            return ImapMessageCopyResult::Err { context, err };
        }

        let Some(Tagged { body, .. }) = tagged else {
            let err = ImapMessageCopyError::MissingTagged;
            return ImapMessageCopyResult::Err { context, err };
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
                ImapMessageCopyResult::Ok { context, copyuid }
            }
            StatusKind::No => ImapMessageCopyResult::Err {
                context,
                err: ImapMessageCopyError::No(body.text.to_string()),
            },
            StatusKind::Bad => ImapMessageCopyResult::Err {
                context,
                err: ImapMessageCopyError::Bad(body.text.to_string()),
            },
        }
    }
}
