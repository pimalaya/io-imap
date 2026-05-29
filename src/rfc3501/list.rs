//! I/O-free coroutine to send an IMAP LIST command.

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        command::{Command, CommandBody},
        core::{QuotedChar, TagGenerator},
        flag::FlagNameAttribute,
        mailbox::{ListMailbox, Mailbox},
        response::{Data, StatusKind, Tagged},
    },
};
use log::trace;
use thiserror::Error;

use crate::coroutine::{ImapCoroutine, ImapCoroutineState};
use crate::{
    rfc3501::mailbox::{decode_inplace, encode_inplace},
    send::*,
};

/// Output of the IMAP `LIST` (and `LSUB`) command: one row per matched
/// mailbox `(mailbox, hierarchy delimiter, attributes)`.
pub type ImapMailboxListing = Vec<(
    Mailbox<'static>,
    Option<QuotedChar>,
    Vec<FlagNameAttribute<'static>>,
)>;

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum ImapMailboxListError {
    #[error("IMAP LIST NO error: {0}")]
    No(String),
    #[error("IMAP LIST BAD error: {0}")]
    Bad(String),
    #[error("IMAP LIST BYE error: {0}")]
    Bye(String),

    #[error("No IMAP LIST tagged response returned by the server")]
    MissingTagged,

    #[error("Send IMAP LIST command error")]
    Send(#[from] SendImapCommandError),
}

/// I/O-free coroutine to send an IMAP LIST command.
pub struct ImapMailboxList {
    send: SendImapCommand<CommandCodec>,
}

impl ImapMailboxList {
    /// Creates a new coroutine.
    pub fn new(mut reference: Mailbox<'static>, mailbox_wildcard: ListMailbox<'static>) -> Self {
        trace!("list IMAP mailboxes: {reference:?} {mailbox_wildcard:?}");
        encode_inplace(&mut reference);

        let body = CommandBody::List {
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

impl ImapCoroutine for ImapMailboxList {
    type Output = ImapMailboxListing;
    type Error = ImapMailboxListError;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Output, Self::Error> {
        let (data, tagged, bye) = match self.send.resume(fragmentizer, arg) {
            SendImapCommandResult::WantsRead => return ImapCoroutineState::WantsRead,
            SendImapCommandResult::WantsWrite(bytes) => {
                return ImapCoroutineState::WantsWrite(bytes);
            }
            SendImapCommandResult::Ok {
                data, tagged, bye, ..
            } => (data, tagged, bye),
            SendImapCommandResult::Err(err) => return ImapCoroutineState::Err(err.into()),
        };

        if let Some(bye) = bye {
            return ImapCoroutineState::Err(ImapMailboxListError::Bye(bye.text.to_string()));
        }

        let Some(Tagged { body, .. }) = tagged else {
            return ImapCoroutineState::Err(ImapMailboxListError::MissingTagged);
        };

        let mut mailboxes = Vec::new();

        for data in data {
            if let Data::List {
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
            StatusKind::Ok => ImapCoroutineState::Done(mailboxes),
            StatusKind::No => {
                ImapCoroutineState::Err(ImapMailboxListError::No(body.text.to_string()))
            }
            StatusKind::Bad => {
                ImapCoroutineState::Err(ImapMailboxListError::Bad(body.text.to_string()))
            }
        }
    }
}
