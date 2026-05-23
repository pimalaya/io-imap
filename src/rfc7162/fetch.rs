//! CONDSTORE / QRESYNC modifier support for the base FETCH coroutine
//! ([`crate::rfc3501::fetch::ImapMessageFetch`]).
//!
//! RFC 7162 introduces the `CHANGEDSINCE <mod-sequence>` FETCH
//! modifier (§3.1.2) and the `VANISHED` FETCH modifier (§3.2.6); the
//! FETCH command itself is unchanged. Callers build a list of
//! [`FetchModifier`] variants and pass it to
//! [`ImapMessageFetch::with_modifiers`] alongside the usual
//! `sequence_set` / item-names / `uid` arguments.

use imap_codec::{
    CommandCodec,
    imap_types::{
        command::{Command, CommandBody, FetchModifier},
        fetch::MacroOrMessageDataItemNames,
        sequence::SequenceSet,
    },
};

use crate::{context::ImapContext, rfc3501::fetch::ImapMessageFetch, send::SendImapCommand};

impl ImapMessageFetch {
    /// Creates a new coroutine for FETCH (or UID FETCH) with the
    /// given modifier list. Pass `[FetchModifier::ChangedSince(m)]`
    /// for CONDSTORE-style CHANGEDSINCE; pass
    /// `[FetchModifier::ChangedSince(m), FetchModifier::Vanished]`
    /// for the QRESYNC bundle.
    pub fn with_modifiers(
        mut context: ImapContext,
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
        // SAFETY: tag is always valid
        let command = Command::new(context.generate_tag(), body).unwrap();
        Self {
            send: SendImapCommand::new(context, CommandCodec::new(), command),
        }
    }
}
