//! I/O-free coroutine to send an IMAP ENABLE command.

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        command::{Command, CommandBody},
        core::{TagGenerator, Vec1},
        extensions::enable::CapabilityEnable,
        response::{Data, StatusKind, Tagged},
    },
};
use thiserror::Error;

use crate::coroutine::*;
use crate::send::*;

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum ImapExtensionEnableError {
    #[error("IMAP ENABLE NO error: {0}")]
    No(String),
    #[error("IMAP ENABLE BAD error: {0}")]
    Bad(String),
    #[error("IMAP ENABLE BYE error: {0}")]
    Bye(String),

    #[error("No IMAP ENABLE tagged response returned by the server")]
    MissingTagged,

    #[error("Send IMAP ENABLE command error")]
    Send(#[from] SendImapCommandError),
}

/// I/O-free coroutine to send an IMAP ENABLE command.
pub struct ImapExtensionEnable {
    send: SendImapCommand<CommandCodec>,
}

impl ImapExtensionEnable {
    /// Creates a new coroutine.
    pub fn new(capabilities: Vec1<CapabilityEnable<'static>>) -> Self {
        let body = CommandBody::Enable { capabilities };
        let mut tag = TagGenerator::new();
        // SAFETY: tag is always valid
        let command = Command::new(tag.generate(), body).unwrap();
        Self {
            send: SendImapCommand::new(CommandCodec::new(), command),
        }
    }
}

impl ImapCoroutine for ImapExtensionEnable {
    type Yield = ImapYield;
    type Return = Result<Option<Vec<CapabilityEnable<'static>>>, ImapExtensionEnableError>;

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
            return ImapCoroutineState::Complete(Err(ImapExtensionEnableError::Bye(
                bye.text.to_string(),
            )));
        }

        let Some(Tagged { body, .. }) = tagged else {
            return ImapCoroutineState::Complete(Err(ImapExtensionEnableError::MissingTagged));
        };

        let mut enabled = None;
        for data in data {
            if let Data::Enabled { capabilities } = data {
                enabled = Some(capabilities);
            }
        }

        match body.kind {
            StatusKind::Ok => ImapCoroutineState::Complete(Ok(enabled)),
            StatusKind::No => ImapCoroutineState::Complete(Err(ImapExtensionEnableError::No(
                body.text.to_string(),
            ))),
            StatusKind::Bad => ImapCoroutineState::Complete(Err(ImapExtensionEnableError::Bad(
                body.text.to_string(),
            ))),
        }
    }
}
