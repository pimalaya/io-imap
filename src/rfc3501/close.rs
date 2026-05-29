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

use crate::coroutine::*;
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
    type Yield = ImapYield;
    type Return = Result<(), ImapMailboxCloseError>;

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
            return ImapCoroutineState::Complete(Err(ImapMailboxCloseError::Bye(
                bye.text.to_string(),
            )));
        }

        let Some(Tagged { body, .. }) = tagged else {
            return ImapCoroutineState::Complete(Err(ImapMailboxCloseError::MissingTagged));
        };

        match body.kind {
            StatusKind::Ok => ImapCoroutineState::Complete(Ok(())),
            StatusKind::No => {
                ImapCoroutineState::Complete(Err(ImapMailboxCloseError::No(body.text.to_string())))
            }
            StatusKind::Bad => {
                ImapCoroutineState::Complete(Err(ImapMailboxCloseError::Bad(body.text.to_string())))
            }
        }
    }
}

impl Default for ImapMailboxClose {
    fn default() -> Self {
        Self::new()
    }
}
