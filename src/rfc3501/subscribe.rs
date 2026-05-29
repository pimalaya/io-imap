//! I/O-free coroutine to send an IMAP SUBSCRIBE command.

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

use crate::coroutine::{ImapCoroutine, ImapCoroutineState};
use crate::{rfc3501::mailbox::encode_inplace, send::*};

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum ImapMailboxSubscribeError {
    #[error("IMAP SUBSCRIBE NO error: {0}")]
    No(String),
    #[error("IMAP SUBSCRIBE BAD error: {0}")]
    Bad(String),
    #[error("IMAP SUBSCRIBE BYE error: {0}")]
    Bye(String),

    #[error("No IMAP SUBSCRIBE tagged response returned by the server")]
    MissingTagged,

    #[error("Send IMAP SUBSCRIBE command error")]
    Send(#[from] SendImapCommandError),
}

/// I/O-free coroutine to send an IMAP SUBSCRIBE command.
pub struct ImapMailboxSubscribe {
    send: SendImapCommand<CommandCodec>,
}

impl ImapMailboxSubscribe {
    /// Creates a new coroutine.
    pub fn new(mut mailbox: Mailbox<'static>) -> Self {
        encode_inplace(&mut mailbox);
        let body = CommandBody::Subscribe { mailbox };
        let mut tag = TagGenerator::new();
        // SAFETY: tag is always valid
        let command = Command::new(tag.generate(), body).unwrap();
        Self {
            send: SendImapCommand::new(CommandCodec::new(), command),
        }
    }
}

impl ImapCoroutine for ImapMailboxSubscribe {
    type Output = ();
    type Error = ImapMailboxSubscribeError;

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
            return ImapCoroutineState::Err(ImapMailboxSubscribeError::Bye(bye.text.to_string()));
        }

        let Some(Tagged { body, .. }) = tagged else {
            return ImapCoroutineState::Err(ImapMailboxSubscribeError::MissingTagged);
        };

        match body.kind {
            StatusKind::Ok => ImapCoroutineState::Done(()),
            StatusKind::No => {
                ImapCoroutineState::Err(ImapMailboxSubscribeError::No(body.text.to_string()))
            }
            StatusKind::Bad => {
                ImapCoroutineState::Err(ImapMailboxSubscribeError::Bad(body.text.to_string()))
            }
        }
    }
}
