//! CONDSTORE / QRESYNC modifier support for the base FETCH coroutine
//! ([`crate::rfc3501::fetch::ImapMessageFetch`]).

use imap_codec::{
    CommandCodec,
    imap_types::{
        command::{Command, CommandBody, FetchModifier},
        core::TagGenerator,
        fetch::MacroOrMessageDataItemNames,
        sequence::SequenceSet,
    },
};

use crate::{rfc3501::fetch::ImapMessageFetch, send::SendImapCommand};

impl ImapMessageFetch {
    /// Creates a new coroutine for FETCH (or UID FETCH) with the
    /// given modifier list. Pass `[FetchModifier::ChangedSince(m)]`
    /// for CONDSTORE-style CHANGEDSINCE; pass
    /// `[FetchModifier::ChangedSince(m), FetchModifier::Vanished]`
    /// for the QRESYNC bundle.
    pub fn with_modifiers(
        sequence_set: SequenceSet,
        macro_or_item_names: MacroOrMessageDataItemNames<'static>,
        uid: bool,
        modifiers: impl IntoIterator<Item = FetchModifier>,
    ) -> Self {
        let body = CommandBody::Fetch {
            modifiers: modifiers.into_iter().collect(),
            sequence_set,
            macro_or_item_names,
            uid,
        };
        let mut tag = TagGenerator::new();
        // SAFETY: tag is always valid
        let command = Command::new(tag.generate(), body).unwrap();
        Self {
            send: SendImapCommand::new(CommandCodec::new(), command),
        }
    }
}
