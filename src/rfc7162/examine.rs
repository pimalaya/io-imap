//! CONDSTORE / QRESYNC parameter builders for the base EXAMINE
//! coroutine ([`crate::rfc3501::examine::ImapMailboxExamine`]).
//!
//! RFC 7162 obsoletes RFC 4551 (CONDSTORE) and RFC 5162 (original
//! QRESYNC), bundling both into a single extension. The EXAMINE
//! command itself is unchanged from RFC 3501; CONDSTORE / QRESYNC
//! only add new [`SelectParameter`] variants (which EXAMINE shares
//! with SELECT) and tag new fields on the existing EXAMINE response
//! (`HIGHESTMODSEQ`, `VANISHED (EARLIER)`, implicit `* FETCH`).
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
    rfc3501::{examine::ImapMailboxExamine, mailbox::encode_inplace},
    send::SendImapCommand,
};

impl ImapMailboxExamine {
    /// Creates a new coroutine for EXAMINE with no parameters.
    pub fn with_parameters(
        mut context: ImapContext,
        mut mailbox: Mailbox<'static>,
        params: impl IntoIterator<Item = SelectParameter>,
    ) -> Self {
        // Stash the decoded form for the context, then encode the
        // copy that goes on the wire.
        let examine_state = ImapCurrentMailboxState::Selected(mailbox.clone());
        encode_inplace(&mut mailbox);

        let body = CommandBody::Examine {
            mailbox,
            parameters: params.into_iter().collect(),
        };

        // SAFETY: tag is always valid
        let command = Command::new(context.generate_tag(), body).unwrap();

        Self {
            examine_state,
            send: SendImapCommand::new(context, CommandCodec::new(), command),
        }
    }
}
