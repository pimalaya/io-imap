#![no_main]

//! Coverage-guided fuzz target for the batched FETCH body stream,
//! driven the way a consumer streams bodies to disk. Its oracle: the
//! coroutine never panics, never yields body octets outside a message,
//! and never announces a body over its options' limit.

#[path = "reads.rs"]
mod reads;

use std::mem;

use io_imap::{
    codec::fragmentizer::Fragmentizer,
    coroutine::*,
    rfc3501::fetch_stream_batch::{
        ImapMessageFetchStreamBatch, ImapMessageFetchStreamBatchOptions,
        ImapMessageFetchStreamBatchYield,
    },
    types::sequence::SequenceSet,
};
use libfuzzer_sys::fuzz_target;

use crate::reads::Reads;

/// The largest body the target accepts, small enough to be reached.
const MAX_LITERAL_LEN: u32 = 4096;

fuzz_target!(|data: &[u8]| {
    let mut reads = Reads::new(data);
    let set: SequenceSet = "1:*".try_into().unwrap();
    let opts = ImapMessageFetchStreamBatchOptions {
        uid: true,
        max_literal_len: MAX_LITERAL_LEN,
        ..Default::default()
    };
    let mut coroutine = ImapMessageFetchStreamBatch::new(set, opts);
    let mut fragmentizer = Fragmentizer::new(1024 * 1024);
    let mut arg: Option<Vec<u8>> = None;
    let mut past = Vec::new();
    let mut open = false;

    for _ in 0..100_000 {
        match coroutine.resume(&mut fragmentizer, arg.take().as_deref()) {
            ImapCoroutineState::Complete(_) => return,
            ImapCoroutineState::Yielded(ImapMessageFetchStreamBatchYield::WantsWrite(_)) => {}
            ImapCoroutineState::Yielded(ImapMessageFetchStreamBatchYield::WantsRead) => {
                arg = Some(reads.next().to_vec());
            }
            ImapCoroutineState::Yielded(ImapMessageFetchStreamBatchYield::MessageStart {
                ..
            }) => {
                assert!(!open, "message started within a message");
                open = true;
            }
            ImapCoroutineState::Yielded(ImapMessageFetchStreamBatchYield::BodyChunk(chunk)) => {
                assert!(open, "body chunk outside a message");
                assert!(chunk.len() <= MAX_LITERAL_LEN as usize);
            }
            ImapCoroutineState::Yielded(ImapMessageFetchStreamBatchYield::MessageEnd) => {
                assert!(open, "message ended outside a message");
                open = false;

                if !past.is_empty() {
                    arg = Some(mem::take(&mut past));
                }
            }
            ImapCoroutineState::Yielded(ImapMessageFetchStreamBatchYield::WantsStream { len }) => {
                assert!(open, "body stream outside a message");
                assert!(len <= MAX_LITERAL_LEN);

                let mut left = len as usize;
                while left > 0 {
                    let chunk = reads.next();
                    if chunk.is_empty() {
                        break;
                    }
                    let take = left.min(chunk.len());
                    past.extend_from_slice(&chunk[take..]);
                    left -= take;
                }

                arg = (left > 0).then(Vec::new);
            }
        }
    }
});
