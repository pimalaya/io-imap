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

use crate::coroutine::*;
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
    type Yield = ImapYield;
    type Return = Result<(), ImapMailboxUnselectError>;

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
            return ImapCoroutineState::Complete(Err(ImapMailboxUnselectError::Bye(
                bye.text.to_string(),
            )));
        }

        let Some(Tagged { body, .. }) = tagged else {
            return ImapCoroutineState::Complete(Err(ImapMailboxUnselectError::MissingTagged));
        };

        match body.kind {
            StatusKind::Ok => ImapCoroutineState::Complete(Ok(())),
            StatusKind::No => ImapCoroutineState::Complete(Err(ImapMailboxUnselectError::No(
                body.text.to_string(),
            ))),
            StatusKind::Bad => ImapCoroutineState::Complete(Err(ImapMailboxUnselectError::Bad(
                body.text.to_string(),
            ))),
        }
    }
}

impl Default for ImapMailboxUnselect {
    fn default() -> Self {
        Self::new()
    }
}
