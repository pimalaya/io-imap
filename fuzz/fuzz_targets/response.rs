#![no_main]

//! Coverage-guided fuzz target for the response side of the commonest
//! coroutines. One oracle: whatever a server sends, however it is
//! segmented, a coroutine completes or asks for more, never panics.
//!
//! The greeting and STARTTLS coroutines are in, since they read before
//! TLS on a plaintext connection, where anyone on the path speaks.

#[path = "reads.rs"]
mod reads;

use core::num::NonZeroU32;

use io_imap::{
    codec::fragmentizer::Fragmentizer,
    coroutine::*,
    rfc3501::{
        examine::{ImapMailboxExamine, ImapMailboxExamineOptions},
        fetch::{ImapMessageFetch, ImapMessageFetchOptions},
        fetch_stream::{ImapMessageFetchStream, ImapMessageFetchStreamYield},
        greeting::{ImapGreetingGet, ImapGreetingGetOptions},
        list::ImapMailboxList,
        search::{ImapMessageSearch, ImapMessageSearchOptions},
        select::ImapMailboxSelect,
        starttls::ImapStartTls,
    },
    rfc5256::sort::{ImapMessageSort, ImapMessageSortOptions},
    types::{
        core::Vec1,
        extensions::sort::{SortCriterion, SortKey},
        fetch::{MacroOrMessageDataItemNames, MessageDataItemName},
        search::SearchKey,
        sequence::SequenceSet,
    },
};
use libfuzzer_sys::fuzz_target;

use crate::reads::Reads;

/// The most resumes a target allows before giving up on an input.
const MAX_RESUMES: usize = 100_000;

fuzz_target!(|data: &[u8]| {
    let Some((selector, data)) = data.split_first() else {
        return;
    };

    match selector % 10 {
        0 => {
            let opts = ImapGreetingGetOptions {
                ensure_capabilities: true,
            };
            run(ImapGreetingGet::new(opts), data);
        }
        1 => run(ImapStartTls::new(), data),
        2 => {
            let mailbox = "INBOX".try_into().unwrap();
            run(ImapMailboxSelect::new(mailbox, Default::default()), data);
        }
        3 => {
            let mailbox = "INBOX".try_into().unwrap();
            let opts = ImapMailboxExamineOptions::default();
            run(ImapMailboxExamine::new(mailbox, opts), data);
        }
        4 => {
            let reference = "".try_into().unwrap();
            run(ImapMailboxList::new(reference, "*".try_into().unwrap()), data);
        }
        5 => {
            let opts = ImapMessageSearchOptions { uid: true };
            run(ImapMessageSearch::new(Vec1::from(SearchKey::All), opts), data);
        }
        6 => {
            let sort = Vec1::from(SortCriterion {
                reverse: true,
                key: SortKey::Date,
            });
            let opts = ImapMessageSortOptions {
                uid: true,
                ..Default::default()
            };
            run(ImapMessageSort::new(sort, Vec1::from(SearchKey::All), opts), data);
        }
        7 => {
            let items = MacroOrMessageDataItemNames::MessageDataItemNames(vec![
                MessageDataItemName::Uid,
                MessageDataItemName::Flags,
                MessageDataItemName::Envelope,
                MessageDataItemName::BodyStructure,
                MessageDataItemName::Rfc822Size,
            ]);
            let opts = ImapMessageFetchOptions {
                uid: true,
                ..Default::default()
            };
            let set: SequenceSet = "1:*".try_into().unwrap();
            run(ImapMessageFetch::new(set, items, opts), data);
        }
        8 => {
            let items = MacroOrMessageDataItemNames::MessageDataItemNames(vec![
                MessageDataItemName::Uid,
                MessageDataItemName::BodyExt {
                    section: None,
                    partial: None,
                    peek: true,
                },
            ]);
            let opts = ImapMessageFetchOptions::default();
            let set: SequenceSet = "1:*".try_into().unwrap();
            run(ImapMessageFetch::new(set, items, opts), data);
        }
        _ => stream(data),
    }
});

/// Drives a coroutine yielding plain reads and writes.
fn run<C: ImapCoroutine<Yield = ImapYield>>(mut coroutine: C, data: &[u8]) {
    let mut reads = Reads::new(data);
    let mut fragmentizer = Fragmentizer::new(1024 * 1024);
    let mut arg = None;

    for _ in 0..MAX_RESUMES {
        match coroutine.resume(&mut fragmentizer, arg.take()) {
            ImapCoroutineState::Complete(_) => return,
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(_)) => {}
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => arg = Some(reads.next()),
        }
    }
}

/// Drives the single-message FETCH body stream.
fn stream(data: &[u8]) {
    let mut reads = Reads::new(data);
    let mut fragmentizer = Fragmentizer::new(1024 * 1024);
    let mut coroutine = ImapMessageFetchStream::new(NonZeroU32::MIN, true);
    let mut arg = None;

    for _ in 0..MAX_RESUMES {
        match coroutine.resume(&mut fragmentizer, arg.take()) {
            ImapCoroutineState::Complete(_) => return,
            ImapCoroutineState::Yielded(ImapMessageFetchStreamYield::WantsRead) => {
                arg = Some(reads.next());
            }
            ImapCoroutineState::Yielded(ImapMessageFetchStreamYield::WantsStream { len }) => {
                let mut left = len as usize;
                while left > 0 {
                    let chunk = reads.next();
                    if chunk.is_empty() {
                        break;
                    }
                    left = left.saturating_sub(chunk.len());
                }
                arg = (left > 0).then_some(&[][..]);
            }
            ImapCoroutineState::Yielded(_) => {}
        }
    }
}
