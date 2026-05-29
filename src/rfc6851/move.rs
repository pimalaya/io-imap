//! I/O-free coroutine to send an IMAP MOVE command.

use alloc::string::{String, ToString};

use imap_codec::{
    CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        command::{Command, CommandBody},
        core::TagGenerator,
        mailbox::Mailbox,
        response::{Code, StatusKind, Tagged},
        sequence::SequenceSet,
    },
};
use thiserror::Error;

use crate::coroutine::{ImapCoroutine, ImapCoroutineState};
use crate::{
    rfc3501::{
        copy::{ImapCopyUid, uid_set_to_vec},
        mailbox::encode_inplace,
    },
    send::*,
};

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

/// I/O-free coroutine to send an IMAP MOVE command.
pub struct ImapMessageMove {
    send: SendImapCommand<CommandCodec>,
}

impl ImapMessageMove {
    /// Creates a new coroutine.
    pub fn new(sequence_set: SequenceSet, mut mailbox: Mailbox<'static>, uid: bool) -> Self {
        encode_inplace(&mut mailbox);
        let body = CommandBody::Move {
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

impl ImapCoroutine for ImapMessageMove {
    type Output = ImapCopyUid;
    type Error = ImapMessageMoveError;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Output, Self::Error> {
        let (tagged, bye) = match self.send.resume(fragmentizer, arg) {
            SendImapCommandResult::WantsRead => return ImapCoroutineState::WantsRead,
            SendImapCommandResult::WantsWrite(bytes) => {
                return ImapCoroutineState::WantsWrite(bytes);
            }
            SendImapCommandResult::Ok { tagged, bye, .. } => (tagged, bye),
            SendImapCommandResult::Err(err) => return ImapCoroutineState::Err(err.into()),
        };

        if let Some(bye) = bye {
            return ImapCoroutineState::Err(ImapMessageMoveError::Bye(bye.text.to_string()));
        }

        let Some(Tagged { body, .. }) = tagged else {
            return ImapCoroutineState::Err(ImapMessageMoveError::MissingTagged);
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
                ImapCoroutineState::Done(copyuid)
            }
            StatusKind::No => {
                ImapCoroutineState::Err(ImapMessageMoveError::No(body.text.to_string()))
            }
            StatusKind::Bad => {
                ImapCoroutineState::Err(ImapMessageMoveError::Bad(body.text.to_string()))
            }
        }
    }
}
