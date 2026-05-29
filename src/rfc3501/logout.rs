//! I/O-free coroutine to send an IMAP LOGOUT command.

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
pub enum ImapLogoutError {
    #[error("IMAP LOGOUT NO error: {0}")]
    No(String),
    #[error("IMAP LOGOUT BAD error: {0}")]
    Bad(String),

    #[error("No IMAP LOGOUT tagged response returned by the server")]
    MissingTagged,
    #[error("No IMAP LOGOUT BYE response returned by the server")]
    MissingBye,

    #[error("Send IMAP LOGOUT command error")]
    Send(#[from] SendImapCommandError),
}

/// I/O-free coroutine to send an IMAP LOGOUT command.
pub struct ImapLogout {
    send: SendImapCommand<CommandCodec>,
}

impl ImapLogout {
    /// Creates a new coroutine.
    pub fn new() -> Self {
        let mut tag = TagGenerator::new();
        // SAFETY: tag is always valid
        let command = Command::new(tag.generate(), CommandBody::Logout).unwrap();
        Self {
            send: SendImapCommand::new(CommandCodec::new(), command),
        }
    }
}

impl ImapCoroutine for ImapLogout {
    type Output = ();
    type Error = ImapLogoutError;

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

        if bye.is_none() {
            return ImapCoroutineState::Err(ImapLogoutError::MissingBye);
        }

        let Some(Tagged { body, .. }) = tagged else {
            return ImapCoroutineState::Err(ImapLogoutError::MissingTagged);
        };

        match body.kind {
            StatusKind::Ok => ImapCoroutineState::Done(()),
            StatusKind::No => ImapCoroutineState::Err(ImapLogoutError::No(body.text.to_string())),
            StatusKind::Bad => ImapCoroutineState::Err(ImapLogoutError::Bad(body.text.to_string())),
        }
    }
}

impl Default for ImapLogout {
    fn default() -> Self {
        Self::new()
    }
}
