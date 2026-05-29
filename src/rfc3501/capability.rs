//! I/O-free coroutine to get capabilities of an IMAP server.

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        command::{Command, CommandBody},
        core::TagGenerator,
        response::{Capability, Code, Data, StatusBody, StatusKind, Tagged},
    },
};
use thiserror::Error;

use crate::coroutine::*;
use crate::send::*;

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum ImapCapabilityGetError {
    #[error("IMAP CAPABILITY NO error: {0}")]
    No(String),
    #[error("IMAP CAPABILITY BAD error: {0}")]
    Bad(String),
    #[error("IMAP CAPABILITY BYE error: {0}")]
    Bye(String),

    #[error("No CAPABILITY tagged response returned by the IMAP server")]
    ExpectedTagged,
    #[error("No CAPABILITY returned by the IMAP server")]
    ExpectedCapability,

    #[error("Send IMAP CAPABILITY command error")]
    Send(#[from] SendImapCommandError),
}

/// I/O-free coroutine to get capabilities of an IMAP server.
pub struct ImapCapabilityGet {
    send: SendImapCommand<CommandCodec>,
}

impl ImapCapabilityGet {
    /// Creates a new coroutine.
    pub fn new() -> Self {
        let mut tag = TagGenerator::new();
        // SAFETY: tag is always valid
        let command = Command::new(tag.generate(), CommandBody::Capability).unwrap();

        Self {
            send: SendImapCommand::new(CommandCodec::new(), command),
        }
    }
}

impl ImapCoroutine for ImapCapabilityGet {
    type Yield = ImapYield;
    type Return = Result<Vec<Capability<'static>>, ImapCapabilityGetError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        let (bye, tagged, data, untagged) = match self.send.resume(fragmentizer, arg) {
            SendImapCommandResult::WantsRead => {
                return ImapCoroutineState::Yielded(ImapYield::WantsRead);
            }
            SendImapCommandResult::WantsWrite(bytes) => {
                return ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes));
            }
            SendImapCommandResult::Ok {
                bye,
                tagged,
                data,
                untagged,
                ..
            } => (bye, tagged, data, untagged),
            SendImapCommandResult::Err(err) => {
                return ImapCoroutineState::Complete(Err(err.into()));
            }
        };

        if let Some(bye) = bye {
            return ImapCoroutineState::Complete(Err(ImapCapabilityGetError::Bye(
                bye.text.to_string(),
            )));
        }

        let Some(Tagged { body, .. }) = tagged else {
            return ImapCoroutineState::Complete(Err(ImapCapabilityGetError::ExpectedTagged));
        };

        let code = match body.kind {
            StatusKind::Ok => body.code,
            StatusKind::No => {
                return ImapCoroutineState::Complete(Err(ImapCapabilityGetError::No(
                    body.text.to_string(),
                )));
            }
            StatusKind::Bad => {
                return ImapCoroutineState::Complete(Err(ImapCapabilityGetError::Bad(
                    body.text.to_string(),
                )));
            }
        };

        let mut new_capability = None;

        if let Some(Code::Capability(capability)) = code {
            new_capability.replace(capability);
        }

        for data in data {
            if let Data::Capability(capability) = data {
                new_capability.replace(capability);
            }
        }

        for StatusBody { code, .. } in untagged {
            if let Some(Code::Capability(capability)) = code {
                new_capability.replace(capability);
            }
        }

        let Some(capability) = new_capability else {
            return ImapCoroutineState::Complete(Err(ImapCapabilityGetError::ExpectedCapability));
        };

        ImapCoroutineState::Complete(Ok(capability.into_iter().collect()))
    }
}

impl Default for ImapCapabilityGet {
    fn default() -> Self {
        Self::new()
    }
}
