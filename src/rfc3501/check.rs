//! I/O-free coroutine to send an IMAP CHECK command.

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
pub enum ImapMailboxCheckError {
    #[error("IMAP CHECK NO error: {0}")]
    No(String),
    #[error("IMAP CHECK BAD error: {0}")]
    Bad(String),
    #[error("IMAP CHECK BYE error: {0}")]
    Bye(String),

    #[error("No IMAP CHECK tagged response returned by the server")]
    MissingTagged,

    #[error("Send IMAP CHECK command error")]
    Send(#[from] SendImapCommandError),
}

/// I/O-free coroutine to send an IMAP CHECK command.
pub struct ImapMailboxCheck {
    send: SendImapCommand<CommandCodec>,
}

impl ImapMailboxCheck {
    /// Creates a new coroutine.
    pub fn new() -> Self {
        let mut tag = TagGenerator::new();
        // SAFETY: tag is always valid
        let command = Command::new(tag.generate(), CommandBody::Check).unwrap();
        Self {
            send: SendImapCommand::new(CommandCodec::new(), command),
        }
    }
}

impl ImapCoroutine for ImapMailboxCheck {
    type Output = ();
    type Error = ImapMailboxCheckError;

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
            return ImapCoroutineState::Err(ImapMailboxCheckError::Bye(bye.text.to_string()));
        }

        let Some(Tagged { body, .. }) = tagged else {
            return ImapCoroutineState::Err(ImapMailboxCheckError::MissingTagged);
        };

        match body.kind {
            StatusKind::Ok => ImapCoroutineState::Done(()),
            StatusKind::No => {
                ImapCoroutineState::Err(ImapMailboxCheckError::No(body.text.to_string()))
            }
            StatusKind::Bad => {
                ImapCoroutineState::Err(ImapMailboxCheckError::Bad(body.text.to_string()))
            }
        }
    }
}

impl Default for ImapMailboxCheck {
    fn default() -> Self {
        Self::new()
    }
}
