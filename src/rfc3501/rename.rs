//! I/O-free coroutine to send an IMAP RENAME command.

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
pub enum ImapMailboxRenameError {
    #[error("IMAP RENAME NO error: {0}")]
    No(String),
    #[error("IMAP RENAME BAD error: {0}")]
    Bad(String),
    #[error("IMAP RENAME BYE error: {0}")]
    Bye(String),

    #[error("No IMAP RENAME tagged response returned by the server")]
    MissingTagged,

    #[error("Send IMAP RENAME command error")]
    Send(#[from] SendImapCommandError),
}

/// I/O-free coroutine to send an IMAP RENAME command.
pub struct ImapMailboxRename {
    send: SendImapCommand<CommandCodec>,
}

impl ImapMailboxRename {
    /// Creates a new coroutine.
    pub fn new(mut from: Mailbox<'static>, mut to: Mailbox<'static>) -> Self {
        encode_inplace(&mut from);
        encode_inplace(&mut to);
        let body = CommandBody::Rename { from, to };
        let mut tag = TagGenerator::new();
        // SAFETY: tag is always valid
        let command = Command::new(tag.generate(), body).unwrap();
        Self {
            send: SendImapCommand::new(CommandCodec::new(), command),
        }
    }
}

impl ImapCoroutine for ImapMailboxRename {
    type Yield = ImapYield;
    type Return = Result<(), ImapMailboxRenameError>;

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
            return ImapCoroutineState::Complete(Err(ImapMailboxRenameError::Bye(
                bye.text.to_string(),
            )));
        }

        let Some(Tagged { body, .. }) = tagged else {
            return ImapCoroutineState::Complete(Err(ImapMailboxRenameError::MissingTagged));
        };

        match body.kind {
            StatusKind::Ok => ImapCoroutineState::Complete(Ok(())),
            StatusKind::No => {
                ImapCoroutineState::Complete(Err(ImapMailboxRenameError::No(body.text.to_string())))
            }
            StatusKind::Bad => ImapCoroutineState::Complete(Err(ImapMailboxRenameError::Bad(
                body.text.to_string(),
            ))),
        }
    }
}
