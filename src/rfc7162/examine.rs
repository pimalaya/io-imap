//! CONDSTORE / QRESYNC parameter builders for the base EXAMINE
//! coroutine ([`crate::rfc3501::examine::ImapMailboxExamine`]).

use imap_codec::{
    CommandCodec,
    imap_types::{
        command::{Command, CommandBody, SelectParameter},
        core::TagGenerator,
        mailbox::Mailbox,
    },
};

use crate::{
    rfc3501::{examine::ImapMailboxExamine, mailbox::encode_inplace},
    send::SendImapCommand,
};

impl ImapMailboxExamine {
    /// Creates a new coroutine for EXAMINE with the given parameters.
    pub fn with_parameters(
        mut mailbox: Mailbox<'static>,
        params: impl IntoIterator<Item = SelectParameter>,
    ) -> Self {
        encode_inplace(&mut mailbox);

        let body = CommandBody::Examine {
            mailbox,
            parameters: params.into_iter().collect(),
        };

        let mut tag = TagGenerator::new();
        // SAFETY: tag is always valid
        let command = Command::new(tag.generate(), body).unwrap();

        Self {
            send: SendImapCommand::new(CommandCodec::new(), command),
        }
    }
}
