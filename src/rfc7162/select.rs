//! CONDSTORE / QRESYNC parameter builders for the base SELECT
//! coroutine ([`crate::rfc3501::select::ImapMailboxSelect`]).
//!
//! RFC 7162 obsoletes RFC 4551 (CONDSTORE) and RFC 5162 (original
//! QRESYNC), bundling both into a single extension. The SELECT
//! command itself is unchanged from RFC 3501; CONDSTORE / QRESYNC
//! only add new [`SelectParameter`] variants and tag new fields on
//! the existing SELECT response (`HIGHESTMODSEQ`, `VANISHED
//! (EARLIER)`, implicit `* FETCH`).
//! [`SelectData`] already surfaces those, so this module only owns
//! the parameter-construction side.
//!
//! [`SelectData`]: crate::rfc3501::select::SelectData

use imap_codec::{
    CommandCodec,
    imap_types::{
        command::{Command, CommandBody, SelectParameter},
        mailbox::Mailbox,
    },
};

use crate::{
    context::{ImapContext, ImapCurrentMailboxState},
    rfc3501::{mailbox::encode_inplace, select::ImapMailboxSelect},
    send::SendImapCommand,
};

impl ImapMailboxSelect {
    /// Creates a new coroutine for SELECT with no parameters.
    pub fn with_parameters(
        mut context: ImapContext,
        mut mailbox: Mailbox<'static>,
        params: impl IntoIterator<Item = SelectParameter>,
    ) -> Self {
        // Stash the decoded form for the context, then encode the
        // copy that goes on the wire.
        let select_state = ImapCurrentMailboxState::Selected(mailbox.clone());
        encode_inplace(&mut mailbox);

        let body = CommandBody::Select {
            mailbox,
            parameters: params.into_iter().collect(),
        };

        // SAFETY: tag is always valid
        let command = Command::new(context.generate_tag(), body).unwrap();

        Self {
            select_state,
            send: SendImapCommand::new(context, CommandCodec::new(), command),
        }
    }
}
