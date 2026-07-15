//! Shared helpers for provider integration tests.
//!
//! Each test runs the raw coroutine loop against a live IMAP
//! server using blocking [`Read`]/[`Write`] on the underlying stream.
//!
//! Each integration test compiles this module on its own and only
//! exercises one transport helper, so the other ends up flagged as
//! dead code; suppress the noise at the module level.

#![allow(dead_code)]

use std::{
    io::{Read, Write},
    num::NonZeroU32,
};

use io_imap::{
    codec::fragmentizer::Fragmentizer,
    coroutine::*,
    rfc3501::{append::*, fetch::*, fetch_stream::*, greeting::*, login::*, logout::*, select::*},
    rfc5256::sort::*,
    types::{
        core::Vec1,
        extensions::sort::{SortCriterion, SortKey},
        fetch::{MacroOrMessageDataItemNames, MessageDataItemName},
        flag::Flag,
        response::Capability,
        search::SearchKey,
        sequence::{SeqOrUid, SequenceSet},
    },
};
use pimalaya_stream::{std::stream::StreamStd, tls::Tls};

const FRAGMENTIZER_MAX_MESSAGE_SIZE: u32 = 100 * 1024 * 1024;

/// Unique subject of the message appended mid-flow, used to recognise it
/// again on FETCH.
const SUBJECT: &[u8] = b"io-imap integration test";

/// A shared end-to-end IMAP test flow.
///
/// Connects via IMAPS (direct TLS) and exercises the following sequence:
///
/// ```text
/// GREETING → LOGIN → SELECT INBOX → APPEND → FETCH → FETCH (stream) → SORT → LOGOUT
/// ```
pub fn run_imaps(host: &str, port: u16, username: &str, password: &str) {
    let _ = env_logger::try_init();
    let stream = StreamStd::connect_tls(host, port, &Tls::default()).expect("TLS connect");
    run(stream, username, password)
}

/// Plain-TCP variant of [`run_imaps`]. Same coroutine flow, no TLS.
pub fn run_imap(host: &str, port: u16, username: &str, password: &str) {
    let _ = env_logger::try_init();
    let stream = StreamStd::connect_tcp(host, port).expect("TCP connect");
    run(stream, username, password)
}

fn run(mut stream: impl Read + Write, username: &str, password: &str) {
    let mut buf = [0u8; 16 * 1024];
    let mut fragmentizer = Fragmentizer::new(FRAGMENTIZER_MAX_MESSAGE_SIZE);

    // NOTE: greeting + capability step.

    let mut coroutine = ImapGreetingGet::new(ImapGreetingGetOptions {
        ensure_capabilities: true,
    });
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(&mut fragmentizer, arg.take()) {
            ImapCoroutineState::Complete(Ok(_)) => break,
            ImapCoroutineState::Complete(Err(err)) => panic!("GREETING: {err}"),
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
                let n = stream.read(&mut buf).expect("greeting read");
                arg = Some(&buf[..n]);
            }
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
                stream.write_all(&bytes).expect("greeting write");
                arg = None;
            }
        }
    }

    // NOTE: login step.

    let opts = ImapLoginOptions {
        ensure_capabilities: true,
        auto_id: None,
    };
    let mut coroutine = ImapLogin::new(username, password, opts).expect("valid credentials");
    let mut arg: Option<&[u8]> = None;

    let capabilities = loop {
        match coroutine.resume(&mut fragmentizer, arg.take()) {
            ImapCoroutineState::Complete(Ok(capabilities)) => break capabilities,
            ImapCoroutineState::Complete(Err(err)) => panic!("LOGIN: {err}"),
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
                let n = stream.read(&mut buf).expect("login read");
                arg = Some(&buf[..n]);
            }
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
                stream.write_all(&bytes).expect("login write");
                arg = None;
            }
        }
    };

    // NOTE: servers without the SORT extension take the SEARCH +
    // FETCH fallback.
    let has_sort = capabilities
        .iter()
        .any(|capability| matches!(capability, Capability::Sort(_)));

    // NOTE: select inbox step.

    let mut coroutine = ImapMailboxSelect::new(
        "INBOX".try_into().unwrap(),
        ImapMailboxSelectOptions::default(),
    );
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(&mut fragmentizer, arg.take()) {
            ImapCoroutineState::Complete(Ok(_)) => break,
            ImapCoroutineState::Complete(Err(err)) => panic!("SELECT: {err:?}"),
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
                let n = stream.read(&mut buf).expect("select read");
                arg = Some(&buf[..n]);
            }
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
                stream.write_all(&bytes).expect("select write");
                arg = None;
            }
        }
    }

    // NOTE: append step.

    let message = b"Date: Mon, 1 Jan 2024 00:00:00 +0000\r\n\
        From: io-imap <test@pimalaya.org>\r\n\
        To: io-imap <test@pimalaya.org>\r\n\
        Subject: io-imap integration test\r\n\
        \r\n\
        Hello from the io-imap integration test.\r\n";

    let opts = ImapMessageAppendOptions {
        flags: vec![Flag::Seen],
        ..Default::default()
    };
    let mut coroutine = ImapMessageAppend::new("INBOX".try_into().unwrap(), message.to_vec(), opts);
    let mut arg: Option<&[u8]> = None;

    let (exists, appenduid) = loop {
        match coroutine.resume(&mut fragmentizer, arg.take()) {
            ImapCoroutineState::Complete(Ok(out)) => break out,
            ImapCoroutineState::Complete(Err(err)) => panic!("APPEND: {err}"),
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
                let n = stream.read(&mut buf).expect("append read");
                arg = Some(&buf[..n]);
            }
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
                stream.write_all(&bytes).expect("append write");
                arg = None;
            }
        }
    };

    // NOTE: prefer the APPENDUID (UIDPLUS); otherwise the appended
    // message is the new highest sequence number, i.e. the EXISTS
    // count.
    let (id, uid) = match appenduid {
        Some((_uid_validity, uid)) => (NonZeroU32::new(uid).expect("non-zero APPENDUID"), true),
        None => {
            let seq = exists.expect("APPEND returned neither APPENDUID nor EXISTS");
            (NonZeroU32::new(seq).expect("non-zero EXISTS"), false)
        }
    };

    // NOTE: fetch (buffered) step.

    let items =
        MacroOrMessageDataItemNames::MessageDataItemNames(vec![MessageDataItemName::Envelope]);
    let mut coroutine = ImapMessageFetch::new(
        SequenceSet::from(SeqOrUid::from(id)),
        items,
        ImapMessageFetchOptions {
            uid,
            ..Default::default()
        },
    );
    let mut arg: Option<&[u8]> = None;

    let fetched = loop {
        match coroutine.resume(&mut fragmentizer, arg.take()) {
            ImapCoroutineState::Complete(Ok(map)) => break map,
            ImapCoroutineState::Complete(Err(err)) => panic!("FETCH: {err}"),
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
                let n = stream.read(&mut buf).expect("fetch read");
                arg = Some(&buf[..n]);
            }
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
                stream.write_all(&bytes).expect("fetch write");
                arg = None;
            }
        }
    };
    assert!(!fetched.is_empty(), "buffered FETCH returned no message");

    // NOTE: fetch (streamed, small chunks) step.

    // NOTE: a deliberately tiny buffer fragments even a small body
    // into many reads, exercising the streaming reassembly as if the
    // content were heavy.
    let mut coroutine = ImapMessageFetchStream::new(id, uid);
    let mut chunk = [0u8; 64];
    let mut body: Vec<u8> = Vec::new();
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(&mut fragmentizer, arg.take()) {
            ImapCoroutineState::Complete(Ok(())) => break,
            ImapCoroutineState::Complete(Err(err)) => panic!("FETCH stream: {err}"),
            ImapCoroutineState::Yielded(ImapMessageFetchStreamYield::WantsRead) => {
                let n = stream.read(&mut chunk).expect("fetch stream read");
                arg = Some(&chunk[..n]);
            }
            ImapCoroutineState::Yielded(ImapMessageFetchStreamYield::WantsWrite(bytes)) => {
                stream.write_all(&bytes).expect("fetch stream write");
                arg = None;
            }
            ImapCoroutineState::Yielded(ImapMessageFetchStreamYield::BodyChunk(bytes)) => {
                body.extend_from_slice(&bytes);
                arg = None;
            }
            ImapCoroutineState::Yielded(ImapMessageFetchStreamYield::WantsStream { len }) => {
                let mut remaining = len as usize;
                while remaining > 0 {
                    let want = remaining.min(chunk.len());
                    let n = stream
                        .read(&mut chunk[..want])
                        .expect("fetch stream body read");
                    if n == 0 {
                        break;
                    }
                    body.extend_from_slice(&chunk[..n]);
                    remaining -= n;
                }
                // NOTE: an empty slice tells the coroutine the
                // socket ran short.
                arg = (remaining > 0).then_some(&[]);
            }
        }
    }
    assert!(
        body.windows(SUBJECT.len()).any(|window| window == SUBJECT),
        "streamed body missing the appended subject"
    );

    // NOTE: sort step.

    let sort_criteria = Vec1::try_from(vec![SortCriterion {
        reverse: true,
        key: SortKey::Date,
    }])
    .unwrap();
    let search_criteria = Vec1::try_from(vec![SearchKey::All]).unwrap();
    let mut coroutine = ImapMessageSort::new(
        sort_criteria,
        search_criteria,
        ImapMessageSortOptions {
            uid: true,
            fallback: !has_sort,
        },
    );
    let mut arg: Option<&[u8]> = None;

    let ids = loop {
        match coroutine.resume(&mut fragmentizer, arg.take()) {
            ImapCoroutineState::Complete(Ok(ids)) => break ids,
            ImapCoroutineState::Complete(Err(err)) => panic!("SORT: {err}"),
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
                let n = stream.read(&mut buf).expect("sort read");
                arg = Some(&buf[..n]);
            }
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
                stream.write_all(&bytes).expect("sort write");
                arg = None;
            }
        }
    };
    assert!(!ids.is_empty(), "SORT returned no ids after APPEND");

    // NOTE: logout step.

    let mut coroutine = ImapLogout::new();
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(&mut fragmentizer, arg.take()) {
            ImapCoroutineState::Complete(Ok(())) => break,
            ImapCoroutineState::Complete(Err(err)) => panic!("LOGOUT: {err}"),
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
                let n = stream.read(&mut buf).expect("logout read");
                arg = Some(&buf[..n]);
            }
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
                stream.write_all(&bytes).expect("logout write");
                arg = None;
            }
        }
    }
}
