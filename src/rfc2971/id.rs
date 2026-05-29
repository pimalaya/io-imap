//! I/O-free coroutine to send an IMAP ID command.

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        command::{Command, CommandBody},
        core::{IString, NString, TagGenerator},
        response::{Data, StatusKind, Tagged},
    },
};
use thiserror::Error;

use crate::coroutine::*;
use crate::send::*;

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum ImapServerIdError {
    #[error("IMAP ID NO error: {0}")]
    No(String),
    #[error("IMAP ID BAD error: {0}")]
    Bad(String),
    #[error("IMAP ID BYE error: {0}")]
    Bye(String),

    #[error("No IMAP ID tagged response returned by the server")]
    MissingTagged,

    #[error("Send IMAP ID command error")]
    Send(#[from] SendImapCommandError),
}

/// I/O-free coroutine to send an IMAP ID command.
pub struct ImapServerId {
    send: SendImapCommand<CommandCodec>,
}

impl ImapServerId {
    /// Creates a new coroutine.
    pub fn new(parameters: Option<Vec<(IString<'static>, NString<'static>)>>) -> Self {
        let body = CommandBody::Id { parameters };
        let mut tag = TagGenerator::new();
        // SAFETY: tag is always valid
        let command = Command::new(tag.generate(), body).unwrap();
        Self {
            send: SendImapCommand::new(CommandCodec::new(), command),
        }
    }
}

impl ImapCoroutine for ImapServerId {
    type Yield = ImapYield;
    type Return = Result<Option<Vec<(IString<'static>, NString<'static>)>>, ImapServerIdError>;

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
            return ImapCoroutineState::Complete(Err(ImapServerIdError::Bye(bye.text.to_string())));
        }

        let Some(Tagged { body, .. }) = tagged else {
            return ImapCoroutineState::Complete(Err(ImapServerIdError::MissingTagged));
        };

        let mut server_id = None;
        for data in data {
            if let Data::Id { parameters } = data {
                server_id = parameters;
            }
        }

        match body.kind {
            StatusKind::Ok => ImapCoroutineState::Complete(Ok(server_id)),
            StatusKind::No => {
                ImapCoroutineState::Complete(Err(ImapServerIdError::No(body.text.to_string())))
            }
            StatusKind::Bad => {
                ImapCoroutineState::Complete(Err(ImapServerIdError::Bad(body.text.to_string())))
            }
        }
    }
}
