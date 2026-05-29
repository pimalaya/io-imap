//! I/O-free coroutine to send an IMAP CLOSE command.

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
pub enum ImapMailboxCloseError {
    #[error("IMAP CLOSE NO error: {0}")]
    No(String),
    #[error("IMAP CLOSE BAD error: {0}")]
    Bad(String),
    #[error("IMAP CLOSE BYE error: {0}")]
    Bye(String),

    #[error("No IMAP CLOSE tagged response returned by the server")]
    MissingTagged,

    #[error("Send IMAP CLOSE command error")]
    Send(#[from] SendImapCommandError),
}

/// I/O-free coroutine to send an IMAP CLOSE command.
pub struct ImapMailboxClose {
    send: SendImapCommand<CommandCodec>,
}

impl ImapMailboxClose {
    /// Creates a new coroutine.
    pub fn new() -> Self {
        let mut tag = TagGenerator::new();
        // SAFETY: tag is always valid
        let command = Command::new(tag.generate(), CommandBody::Close).unwrap();
        Self {
            send: SendImapCommand::new(CommandCodec::new(), command),
        }
    }
}

impl ImapCoroutine for ImapMailboxClose {
    type Output = ();
    type Error = ImapMailboxCloseError;

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
            return ImapCoroutineState::Err(ImapMailboxCloseError::Bye(bye.text.to_string()));
        }

        let Some(Tagged { body, .. }) = tagged else {
            return ImapCoroutineState::Err(ImapMailboxCloseError::MissingTagged);
        };

        match body.kind {
            StatusKind::Ok => ImapCoroutineState::Done(()),
            StatusKind::No => {
                ImapCoroutineState::Err(ImapMailboxCloseError::No(body.text.to_string()))
            }
            StatusKind::Bad => {
                ImapCoroutineState::Err(ImapMailboxCloseError::Bad(body.text.to_string()))
            }
        }
    }
}

impl Default for ImapMailboxClose {
    fn default() -> Self {
        Self::new()
    }
}
