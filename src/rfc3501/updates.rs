//! # Mailbox updates
//!
//! What a server reports of the selected mailbox on its own, in the
//! response to any command (RFC 3501 §7). Returned by
//! [`super::noop::ImapNoop`] and [`super::check::ImapMailboxCheck`].

use core::{num::NonZeroU32, ops::RangeInclusive};

use alloc::vec::Vec;

use imap_codec::imap_types::{core::Vec1, fetch::MessageDataItem, response::Data};

use crate::rfc3501::select::uid_ranges;

/// Unsolicited data on the selected mailbox, in the order received.
#[derive(Clone, Debug, Default)]
pub struct ImapMailboxUpdates {
    /// Number of messages in the mailbox (untagged EXISTS).
    pub exists: Option<u32>,
    /// Number of messages with the `\Recent` flag (untagged RECENT).
    pub recent: Option<u32>,
    /// Sequence numbers of the expunged messages (untagged EXPUNGE).
    ///
    /// Each one shifts the sequence numbers after it, so they apply in
    /// this order.
    pub expunged: Vec<NonZeroU32>,
    /// UIDs of the expunged messages, as inclusive ranges (untagged
    /// VANISHED).
    pub vanished: Vec<RangeInclusive<NonZeroU32>>,
    /// Messages whose data changed, by sequence number (untagged
    /// FETCH).
    pub fetched: Vec<(NonZeroU32, Vec1<MessageDataItem<'static>>)>,
}

impl ImapMailboxUpdates {
    /// Reads the updates off the untagged data of an exchange.
    pub(crate) fn from_data(data: Vec<Data<'static>>) -> Self {
        let mut updates = Self::default();

        for data in data {
            match data {
                Data::Exists(exists) => updates.exists = Some(exists),
                Data::Recent(recent) => updates.recent = Some(recent),
                Data::Expunge(seq) => updates.expunged.push(seq),
                Data::Vanished { known_uids, .. } => {
                    updates.vanished.extend(uid_ranges(&known_uids));
                }
                Data::Fetch { seq, items } => updates.fetched.push((seq, items)),
                _ => {}
            }
        }

        updates
    }
}
