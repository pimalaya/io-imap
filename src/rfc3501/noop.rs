//! I/O-free coroutine to send an IMAP NOOP command.

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
pub enum ImapNoopError {
    #[error("IMAP NOOP NO error: {0}")]
    No(String),
    #[error("IMAP NOOP BAD error: {0}")]
    Bad(String),
    #[error("IMAP NOOP BYE error: {0}")]
    Bye(String),

    #[error("No IMAP NOOP tagged response returned by the server")]
    MissingTagged,

    #[error("Send IMAP NOOP command error")]
    Send(#[from] SendImapCommandError),
}

/// I/O-free coroutine to send an IMAP NOOP command.
pub struct ImapNoop {
    send: SendImapCommand<CommandCodec>,
}

impl ImapNoop {
    /// Creates a new coroutine.
    pub fn new() -> Self {
        let mut tag = TagGenerator::new();
        // SAFETY: tag is always valid
        let command = Command::new(tag.generate(), CommandBody::Noop).unwrap();
        Self {
            send: SendImapCommand::new(CommandCodec::new(), command),
        }
    }
}

impl ImapCoroutine for ImapNoop {
    type Yield = ImapYield;
    type Return = Result<(), ImapNoopError>;

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
            return ImapCoroutineState::Complete(Err(ImapNoopError::Bye(bye.text.to_string())));
        }

        let Some(Tagged { body, .. }) = tagged else {
            return ImapCoroutineState::Complete(Err(ImapNoopError::MissingTagged));
        };

        match body.kind {
            StatusKind::Ok => ImapCoroutineState::Complete(Ok(())),
            StatusKind::No => {
                ImapCoroutineState::Complete(Err(ImapNoopError::No(body.text.to_string())))
            }
            StatusKind::Bad => {
                ImapCoroutineState::Complete(Err(ImapNoopError::Bad(body.text.to_string())))
            }
        }
    }
}

impl Default for ImapNoop {
    fn default() -> Self {
        Self::new()
    }
}
