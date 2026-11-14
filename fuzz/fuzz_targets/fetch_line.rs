#![no_main]

//! Coverage-guided fuzz target for the recovery of a FETCH response
//! that does not decode whole. Each input is the rest of a `* 1 FETCH (`
//! line, then the completion. Its oracle: the FETCH completes or asks
//! for more, never panics, and every failed item it names is bytes the
//! server sent.

#[path = "reads.rs"]
mod reads;

use io_imap::{
    codec::fragmentizer::Fragmentizer,
    coroutine::*,
    rfc3501::fetch::{ImapMessageFetch, ImapMessageFetchOptions},
    types::{
        fetch::{Macro, MacroOrMessageDataItemNames},
        sequence::SequenceSet,
    },
};
use libfuzzer_sys::fuzz_target;

use crate::reads::Reads;

/// The most resumes the target allows before giving up on an input.
const MAX_RESUMES: usize = 100_000;

fuzz_target!(|data: &[u8]| {
    let Some((size, line)) = data.split_first() else {
        return;
    };

    let mut input = vec![*size];
    input.extend_from_slice(b"* 1 FETCH (");
    input.extend_from_slice(line);
    input.extend_from_slice(b"\r\nA1 OK done\r\n");

    let set: SequenceSet = "1:*".try_into().unwrap();
    let items = MacroOrMessageDataItemNames::Macro(Macro::Full);
    let mut coroutine = ImapMessageFetch::new(set, items, ImapMessageFetchOptions::default());
    let mut fragmentizer = Fragmentizer::new(1024 * 1024);
    let mut reads = Reads::new(&input);
    let mut arg = None;

    for _ in 0..MAX_RESUMES {
        match coroutine.resume(&mut fragmentizer, arg.take()) {
            ImapCoroutineState::Complete(Ok(out)) => {
                for partial in &out.partial {
                    assert!(!partial.failed.is_empty());

                    for item in &partial.failed {
                        let raw = item.raw.declassify();
                        assert!(String::from_utf8_lossy(raw).starts_with(&item.name));
                        assert!(input.windows(raw.len()).any(|bytes| bytes == &**raw));
                    }
                }

                return;
            }
            ImapCoroutineState::Complete(Err(_)) => return,
            ImapCoroutineState::Yielded(ImapYield::WantsTag) => arg = Some(b"A1".as_slice()),
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(_)) => {}
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => arg = Some(reads.next()),
        }
    }
});
