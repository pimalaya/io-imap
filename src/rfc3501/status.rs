//! I/O-free coroutine to send an IMAP STATUS command.

use alloc::{borrow::Cow, string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        command::{Command, CommandBody},
        core::TagGenerator,
        mailbox::Mailbox,
        response::{Data, StatusKind, Tagged},
        status::{StatusDataItem, StatusDataItemName},
    },
};
use log::trace;
use thiserror::Error;

use crate::coroutine::{ImapCoroutine, ImapCoroutineState};
use crate::{rfc3501::mailbox::encode_inplace, send::*};

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum ImapMailboxStatusError {
    #[error("IMAP STATUS NO error: {0}")]
    No(String),
    #[error("IMAP STATUS BAD error: {0}")]
    Bad(String),
    #[error("IMAP STATUS BYE error: {0}")]
    Bye(String),

    #[error("No IMAP STATUS tagged response returned by the server")]
    MissingTagged,

    #[error("Send IMAP STATUS command error")]
    Send(#[from] SendImapCommandError),
}

/// I/O-free coroutine to send an IMAP STATUS command.
pub struct ImapMailboxStatus {
    send: SendImapCommand<CommandCodec>,
}

impl ImapMailboxStatus {
    /// Creates a new coroutine.
    pub fn new(
        mut mailbox: Mailbox<'static>,
        item_names: impl Into<Cow<'static, [StatusDataItemName]>>,
    ) -> Self {
        trace!("status IMAP mailbox: {mailbox:?}");
        encode_inplace(&mut mailbox);

        let body = CommandBody::Status {
            mailbox,
            item_names: item_names.into(),
        };
        let mut tag = TagGenerator::new();
        // SAFETY: tag is always valid
        let command = Command::new(tag.generate(), body).unwrap();
        Self {
            send: SendImapCommand::new(CommandCodec::new(), command),
        }
    }
}

impl ImapCoroutine for ImapMailboxStatus {
    type Output = Vec<StatusDataItem>;
    type Error = ImapMailboxStatusError;

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
            return ImapCoroutineState::Err(ImapMailboxStatusError::Bye(bye.text.to_string()));
        }

        let Some(Tagged { body, .. }) = tagged else {
            return ImapCoroutineState::Err(ImapMailboxStatusError::MissingTagged);
        };

        let mut items = Vec::new();
        for data in data {
            if let Data::Status {
                mailbox: _,
                items: status_items,
            } = data
            {
                items.extend(status_items.into_owned());
            }
        }

        match body.kind {
            StatusKind::Ok => ImapCoroutineState::Done(items),
            StatusKind::No => {
                ImapCoroutineState::Err(ImapMailboxStatusError::No(body.text.to_string()))
            }
            StatusKind::Bad => {
                ImapCoroutineState::Err(ImapMailboxStatusError::Bad(body.text.to_string()))
            }
        }
    }
}
