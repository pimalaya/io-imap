//! I/O-free coroutine to send an IMAP DELETE command.

use alloc::string::{String, ToString};

use imap_codec::{
    CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        command::{Command, CommandBody},
        core::TagGenerator,
        mailbox::Mailbox,
        response::{StatusKind, Tagged},
    },
};
use thiserror::Error;

use crate::coroutine::*;
use crate::{rfc3501::mailbox::encode_inplace, send::*};

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum ImapMailboxDeleteError {
    #[error("IMAP DELETE NO error: {0}")]
    No(String),
    #[error("IMAP DELETE BAD error: {0}")]
    Bad(String),
    #[error("IMAP DELETE BYE error: {0}")]
    Bye(String),

    #[error("No IMAP DELETE tagged response returned by the server")]
    MissingTagged,

    #[error("Send IMAP DELETE command error")]
    Send(#[from] SendImapCommandError),
}

/// I/O-free coroutine to send an IMAP DELETE command.
pub struct ImapMailboxDelete {
    send: SendImapCommand<CommandCodec>,
}

impl ImapMailboxDelete {
    /// Creates a new coroutine.
    pub fn new(mut mailbox: Mailbox<'static>) -> Self {
        encode_inplace(&mut mailbox);
        let body = CommandBody::Delete { mailbox };
        let mut tag = TagGenerator::new();
        // SAFETY: tag is always valid
        let command = Command::new(tag.generate(), body).unwrap();
        Self {
            send: SendImapCommand::new(CommandCodec::new(), command),
        }
    }
}

impl ImapCoroutine for ImapMailboxDelete {
    type Yield = ImapYield;
    type Return = Result<(), ImapMailboxDeleteError>;

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
            return ImapCoroutineState::Complete(Err(ImapMailboxDeleteError::Bye(
                bye.text.to_string(),
            )));
        }

        let Some(Tagged { body, .. }) = tagged else {
            return ImapCoroutineState::Complete(Err(ImapMailboxDeleteError::MissingTagged));
        };

        match body.kind {
            StatusKind::Ok => ImapCoroutineState::Complete(Ok(())),
            StatusKind::No => {
                ImapCoroutineState::Complete(Err(ImapMailboxDeleteError::No(body.text.to_string())))
            }
            StatusKind::Bad => ImapCoroutineState::Complete(Err(ImapMailboxDeleteError::Bad(
                body.text.to_string(),
            ))),
        }
    }
}
