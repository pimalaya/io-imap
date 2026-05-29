//! I/O-free coroutine to send an IMAP LSUB command.

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        command::{Command, CommandBody},
        core::TagGenerator,
        mailbox::{ListMailbox, Mailbox},
        response::{Data, StatusKind, Tagged},
    },
};
use log::trace;
use thiserror::Error;

use crate::coroutine::*;
use crate::{
    rfc3501::{
        list::ImapMailboxListing,
        mailbox::{decode_inplace, encode_inplace},
    },
    send::*,
};

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum ImapMailboxLsubError {
    #[error("IMAP LSUB NO error: {0}")]
    No(String),
    #[error("IMAP LSUB BAD error: {0}")]
    Bad(String),
    #[error("IMAP LSUB BYE error: {0}")]
    Bye(String),

    #[error("No IMAP LSUB tagged response returned by the server")]
    MissingTagged,

    #[error("Send IMAP LSUB command error")]
    Send(#[from] SendImapCommandError),
}

/// I/O-free coroutine to send an IMAP LSUB command.
pub struct ImapMailboxLsub {
    send: SendImapCommand<CommandCodec>,
}

impl ImapMailboxLsub {
    /// Creates a new coroutine.
    pub fn new(mut reference: Mailbox<'static>, mailbox_wildcard: ListMailbox<'static>) -> Self {
        trace!("lsub IMAP mailboxes: {reference:?} {mailbox_wildcard:?}");
        encode_inplace(&mut reference);

        let body = CommandBody::Lsub {
            reference,
            mailbox_wildcard,
        };
        let mut tag = TagGenerator::new();
        // SAFETY: tag is always valid
        let command = Command::new(tag.generate(), body).unwrap();
        Self {
            send: SendImapCommand::new(CommandCodec::new(), command),
        }
    }
}

impl ImapCoroutine for ImapMailboxLsub {
    type Yield = ImapYield;
    type Return = Result<ImapMailboxListing, ImapMailboxLsubError>;

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
            return ImapCoroutineState::Complete(Err(ImapMailboxLsubError::Bye(
                bye.text.to_string(),
            )));
        }

        let Some(Tagged { body, .. }) = tagged else {
            return ImapCoroutineState::Complete(Err(ImapMailboxLsubError::MissingTagged));
        };

        let mut mailboxes = Vec::new();

        for data in data {
            if let Data::Lsub {
                items,
                delimiter,
                mailbox,
            } = data
            {
                let mut mailbox = mailbox;
                decode_inplace(&mut mailbox);
                mailboxes.push((mailbox, delimiter, items));
            }
        }

        match body.kind {
            StatusKind::Ok => ImapCoroutineState::Complete(Ok(mailboxes)),
            StatusKind::No => {
                ImapCoroutineState::Complete(Err(ImapMailboxLsubError::No(body.text.to_string())))
            }
            StatusKind::Bad => {
                ImapCoroutineState::Complete(Err(ImapMailboxLsubError::Bad(body.text.to_string())))
            }
        }
    }
}
