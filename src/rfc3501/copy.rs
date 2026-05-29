//! I/O-free coroutine to send an IMAP COPY command.

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        command::{Command, CommandBody},
        core::TagGenerator,
        extensions::uidplus::{UidElement, UidSet},
        mailbox::Mailbox,
        response::{Code, StatusKind, Tagged},
        sequence::SequenceSet,
    },
};
use thiserror::Error;

use crate::coroutine::*;
use crate::{rfc3501::mailbox::encode_inplace, send::*};

/// Output of the IMAP `COPY` (and `MOVE`) command: the
/// `[COPYUID uidvalidity src-uids dst-uids]` response code (RFC 4315) if the
/// server returned one, decoded as `(uidvalidity, source UIDs,
/// destination UIDs)`.
pub type ImapCopyUid = Option<(u32, Vec<u32>, Vec<u32>)>;

/// Expand a `UidSet` into a sorted `Vec<u32>`.
pub(crate) fn uid_set_to_vec(uid_set: UidSet) -> Vec<u32> {
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

/// I/O-free coroutine to send an IMAP COPY command.
pub struct ImapMessageCopy {
    send: SendImapCommand<CommandCodec>,
}

impl ImapMessageCopy {
    /// Creates a new coroutine.
    pub fn new(sequence_set: SequenceSet, mut mailbox: Mailbox<'static>, uid: bool) -> Self {
        encode_inplace(&mut mailbox);
        let body = CommandBody::Copy {
            sequence_set,
            mailbox,
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

impl ImapCoroutine for ImapMessageCopy {
    type Yield = ImapYield;
    type Return = Result<ImapCopyUid, ImapMessageCopyError>;

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
            return ImapCoroutineState::Complete(Err(ImapMessageCopyError::Bye(
                bye.text.to_string(),
            )));
        }

        let Some(Tagged { body, .. }) = tagged else {
            return ImapCoroutineState::Complete(Err(ImapMessageCopyError::MissingTagged));
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
                ImapCoroutineState::Complete(Ok(copyuid))
            }
            StatusKind::No => {
                ImapCoroutineState::Complete(Err(ImapMessageCopyError::No(body.text.to_string())))
            }
            StatusKind::Bad => {
                ImapCoroutineState::Complete(Err(ImapMessageCopyError::Bad(body.text.to_string())))
            }
        }
    }
}
