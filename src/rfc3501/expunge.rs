//! I/O-free coroutine to send an IMAP EXPUNGE command.

use core::num::NonZeroU32;

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        command::{Command, CommandBody},
        core::TagGenerator,
        response::{Data, StatusKind, Tagged},
    },
};
use thiserror::Error;

use crate::coroutine::*;
use crate::send::*;

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum ImapMailboxExpungeError {
    #[error("IMAP EXPUNGE NO error: {0}")]
    No(String),
    #[error("IMAP EXPUNGE BAD error: {0}")]
    Bad(String),
    #[error("IMAP EXPUNGE BYE error: {0}")]
    Bye(String),

    #[error("No IMAP EXPUNGE tagged response returned by the server")]
    MissingTagged,

    #[error("Send IMAP EXPUNGE command error")]
    Send(#[from] SendImapCommandError),
}

/// I/O-free coroutine to send an IMAP EXPUNGE command.
pub struct ImapMailboxExpunge {
    send: SendImapCommand<CommandCodec>,
}

impl ImapMailboxExpunge {
    /// Creates a new coroutine.
    pub fn new() -> Self {
        let mut tag = TagGenerator::new();
        // SAFETY: tag is always valid
        let command = Command::new(tag.generate(), CommandBody::Expunge).unwrap();
        Self {
            send: SendImapCommand::new(CommandCodec::new(), command),
        }
    }
}

impl ImapCoroutine for ImapMailboxExpunge {
    type Yield = ImapYield;
    type Return = Result<Vec<NonZeroU32>, ImapMailboxExpungeError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        let (data, tagged, bye) = match self.send.resume(fragmentizer, arg) {
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
            return ImapCoroutineState::Complete(Err(ImapMailboxExpungeError::Bye(
                bye.text.to_string(),
            )));
        }

        let Some(Tagged { body, .. }) = tagged else {
            return ImapCoroutineState::Complete(Err(ImapMailboxExpungeError::MissingTagged));
        };

        let mut expunged = Vec::new();
        for data in data {
            if let Data::Expunge(seq) = data {
                expunged.push(seq);
            }
        }

        match body.kind {
            StatusKind::Ok => ImapCoroutineState::Complete(Ok(expunged)),
            StatusKind::No => ImapCoroutineState::Complete(Err(ImapMailboxExpungeError::No(
                body.text.to_string(),
            ))),
            StatusKind::Bad => ImapCoroutineState::Complete(Err(ImapMailboxExpungeError::Bad(
                body.text.to_string(),
            ))),
        }
    }
}

impl Default for ImapMailboxExpunge {
    fn default() -> Self {
        Self::new()
    }
}
