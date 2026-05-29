//! I/O-free coroutine to send an IMAP UNSELECT command.

use alloc::string::{String, ToString};

use imap_codec::{
    CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        command::{Command, CommandBody},
        core::TagGenerator,
        response::{StatusKind, Tagged},
    },
};
use thiserror::Error;

use crate::coroutine::{ImapCoroutine, ImapCoroutineState};
use crate::send::*;

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum ImapMailboxUnselectError {
    #[error("IMAP UNSELECT NO error: {0}")]
    No(String),
    #[error("IMAP UNSELECT BAD error: {0}")]
    Bad(String),
    #[error("IMAP UNSELECT BYE error: {0}")]
    Bye(String),

    #[error("No IMAP UNSELECT tagged response returned by the server")]
    MissingTagged,

    #[error("Send IMAP UNSELECT command error")]
    Send(#[from] SendImapCommandError),
}

/// I/O-free coroutine to send an IMAP UNSELECT command.
pub struct ImapMailboxUnselect {
    send: SendImapCommand<CommandCodec>,
}

impl ImapMailboxUnselect {
    /// Creates a new coroutine.
    pub fn new() -> Self {
        let mut tag = TagGenerator::new();
        // SAFETY: tag is always valid
        let command = Command::new(tag.generate(), CommandBody::Unselect).unwrap();
        Self {
            send: SendImapCommand::new(CommandCodec::new(), command),
        }
    }
}

impl ImapCoroutine for ImapMailboxUnselect {
    type Output = ();
    type Error = ImapMailboxUnselectError;

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
            return ImapCoroutineState::Err(ImapMailboxUnselectError::Bye(bye.text.to_string()));
        }

        let Some(Tagged { body, .. }) = tagged else {
            return ImapCoroutineState::Err(ImapMailboxUnselectError::MissingTagged);
        };

        match body.kind {
            StatusKind::Ok => ImapCoroutineState::Done(()),
            StatusKind::No => {
                ImapCoroutineState::Err(ImapMailboxUnselectError::No(body.text.to_string()))
            }
            StatusKind::Bad => {
                ImapCoroutineState::Err(ImapMailboxUnselectError::Bad(body.text.to_string()))
            }
        }
    }
}

impl Default for ImapMailboxUnselect {
    fn default() -> Self {
        Self::new()
    }
}
