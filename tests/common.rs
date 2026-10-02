//! Shared helpers for provider integration tests.
//!
//! Two flows run against a live IMAP server. [`run_imaps`] and
//! [`run_imap`] drive the raw coroutine loop over blocking
//! [`Read`]/[`Write`]; [`run_client`] drives [`ImapClientStd`], from
//! [`ImapClientStd::connect`] through every command the server
//! advertises, and tears down what it created.
//!
//! Each integration test compiles this module on its own and only
//! exercises some of these helpers, so the rest end up flagged as dead
//! code; suppress the noise at the module level.

#![allow(dead_code)]

use std::{
    io::{Read, Write},
    num::NonZeroU32,
    panic::{self, AssertUnwindSafe},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use io_imap::{
    client::{
        ImapClient, ImapClientStd, ImapClientStdConnectOptions, ImapMailboxWatchStreamOptions,
    },
    codec::fragmentizer::Fragmentizer,
    coroutine::*,
    rfc2971::id::*,
    rfc3501::{
        append::*, copy::*, expunge::*, fetch::*, fetch_stream::*, greeting::*, login::*,
        logout::*, search::*, select::*, store::*,
    },
    rfc5256::{sort::*, thread::*},
    rfc6851::r#move::*,
    types::{
        core::{AString, Vec1},
        extensions::{
            enable::CapabilityEnable,
            sort::{SortCriterion, SortKey},
            thread::ThreadingAlgorithm,
        },
        fetch::{MacroOrMessageDataItemNames, MessageDataItemName},
        flag::{Flag, StoreType},
        mailbox::{ListMailbox, Mailbox},
        response::Capability,
        search::SearchKey,
        sequence::{SeqOrUid, SequenceSet},
        status::StatusDataItemName,
    },
    watch::*,
};
use io_sasl::mechanism::Sasl;
use pimalaya_stream::{
    stream::{Stream, TcpConnectOptions, TlsConnectOptions},
    tls::Tls,
};
use url::Url;

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
    let opts = TlsConnectOptions {
        tls: Tls::default(),
        ..Default::default()
    };
    let stream = Stream::connect_tls(host, port, opts).expect("TLS connect");
    run(stream, username, password)
}

/// Plain-TCP variant of [`run_imaps`]. Same coroutine flow, no TLS.
pub fn run_imap(host: &str, port: u16, username: &str, password: &str) {
    let _ = env_logger::try_init();
    let opts = TcpConnectOptions::default();
    let stream = Stream::connect_tcp(host, port, opts).expect("TCP connect");
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

    // NOTE: a unique Message-ID keeps runs apart: Fastmail refuses
    // APPEND once a mailbox holds too many identical messages.
    let message = format!(
        "Date: Mon, 1 Jan 2024 00:00:00 +0000\r\n\
         Message-ID: <io-imap-{}@pimalaya.org>\r\n\
         From: io-imap <test@pimalaya.org>\r\n\
         To: io-imap <test@pimalaya.org>\r\n\
         Subject: io-imap integration test\r\n\
         \r\n\
         Hello from the io-imap integration test.\r\n",
        unique_suffix(),
    );

    let opts = ImapMessageAppendOptions {
        flags: vec![Flag::Seen],
        ..Default::default()
    };
    let mut coroutine =
        ImapMessageAppend::new("INBOX".try_into().unwrap(), message.into_bytes(), opts);
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

    // NOTE: cleanup step. Sweeps every copy by subject, so leftovers of
    // aborted runs go too.

    let criteria = Vec1::from(SearchKey::Subject(
        AString::try_from("io-imap integration test").unwrap(),
    ));
    let mut coroutine = ImapMessageSearch::new(criteria, ImapMessageSearchOptions { uid: true });
    let mut arg: Option<&[u8]> = None;

    let uids = loop {
        match coroutine.resume(&mut fragmentizer, arg.take()) {
            ImapCoroutineState::Complete(Ok(uids)) => break uids,
            ImapCoroutineState::Complete(Err(err)) => panic!("UID SEARCH: {err}"),
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
                let n = stream.read(&mut buf).expect("search read");
                arg = Some(&buf[..n]);
            }
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
                stream.write_all(&bytes).expect("search write");
                arg = None;
            }
        }
    };

    let set =
        SequenceSet::try_from(uids.as_slice()).expect("UID SEARCH found the appended message");
    let mut coroutine = ImapMessageStoreSilent::new(
        set,
        StoreType::Add,
        vec![Flag::Deleted],
        ImapMessageStoreOptions { uid: true },
    );
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(&mut fragmentizer, arg.take()) {
            ImapCoroutineState::Complete(Ok(())) => break,
            ImapCoroutineState::Complete(Err(err)) => panic!("UID STORE \\Deleted: {err}"),
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
                let n = stream.read(&mut buf).expect("store read");
                arg = Some(&buf[..n]);
            }
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
                stream.write_all(&bytes).expect("store write");
                arg = None;
            }
        }
    }

    let mut coroutine = ImapMailboxExpunge::new();
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(&mut fragmentizer, arg.take()) {
            ImapCoroutineState::Complete(Ok(_)) => break,
            ImapCoroutineState::Complete(Err(err)) => panic!("EXPUNGE: {err}"),
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
                let n = stream.read(&mut buf).expect("expunge read");
                arg = Some(&buf[..n]);
            }
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
                stream.write_all(&bytes).expect("expunge write");
                arg = None;
            }
        }
    }

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

/// A shared end-to-end flow over [`ImapClientStd`], the client layer
/// consumers use.
///
/// [`ImapClientStd::connect`] opens the session (TLS, greeting, SASL),
/// then one connection drives the command surface while a second one
/// holds a watch on the test mailbox:
///
/// ```text
/// CONNECT → CAPABILITY → NOOP → RAW → ID → ENABLE → LIST → LSUB
///   → CREATE ×2 → RENAME → SUBSCRIBE → LSUB → UNSUBSCRIBE → STATUS
///   ┌ guarded by with_cleanup ───────────────────────────────────┐
///   │ → APPEND → APPEND (stream) → watch (IDLE) sees an APPEND   │
///   │ → EXAMINE → UNSELECT → SELECT → CHECK → SEARCH → FETCH     │
///   │ → FETCH body (stream) → FETCH bodies (stream) → SORT       │
///   │ → THREAD → STORE → COPY → MOVE → UID EXPUNGE → EXPUNGE     │
///   │ → CLOSE                                                    │
///   └────────────────────────────────────────────────────────────┘
///   → teardown: messages to \Trash and purged there, mailboxes
///     deleted, LOGOUT
/// ```
///
/// Extensions the server does not advertise (ENABLE, UNSELECT, SORT,
/// THREAD, MOVE, UIDPLUS) are skipped rather than failed.
pub fn run_client(url: &str, sasl: Sasl) {
    let _ = env_logger::try_init();
    let url = Url::parse(url).expect("parse IMAP URL");

    let (mut client, capabilities) = connect(&url, &sasl);
    assert!(!capabilities.is_empty(), "no capability after connect");

    let capabilities = client.capability().expect("CAPABILITY");
    let has = |capability: Capability<'static>| capabilities.contains(&capability);

    client.noop().expect("NOOP");

    let raw = client.raw(b"raw1 NOOP\r\n").expect("RAW");
    assert!(raw.contains("raw1 OK"), "RAW missed its tagged OK: {raw}");

    client.id(ImapServerIdOptions::default()).expect("ID");

    if has(Capability::Enable) {
        let condstore = Vec1::from(CapabilityEnable::CondStore);
        client.enable(condstore).expect("ENABLE");
    }

    let all = || ListMailbox::try_from("*").unwrap();
    let listing = client.list(mailbox("INBOX"), all()).expect("LIST");
    assert!(!listing.is_empty(), "LIST returned no mailbox");
    client.lsub(mailbox("INBOX"), all()).expect("LSUB");

    let trash = listing
        .iter()
        .find(|(_, _, attributes)| {
            attributes
                .iter()
                .any(|attribute| attribute.to_string().eq_ignore_ascii_case("\\Trash"))
        })
        .map(|(mailbox, _, _)| mailbox.clone());

    let name = format!("io-imap-test-{}", unique_suffix());
    let created = format!("{name}-created");
    let renamed = format!("{name}-renamed");
    let copied = format!("{name}-copied");

    // --- CREATE, RENAME, SUBSCRIBE ---

    client.create(mailbox(&created)).expect("CREATE");
    client.create(mailbox(&copied)).expect("CREATE copy target");

    // NOTE: from here on the account holds real mailboxes, so every
    // exit path has to remove them. See with_cleanup.
    with_cleanup(
        &mut client,
        |client| {
            client
                .rename(mailbox(&created), mailbox(&renamed))
                .expect("RENAME");
            client_body(client, &url, &sasl, &capabilities, &renamed, &copied);
        },
        |client| {
            // NOTE: the body may have failed mid-command, leaving the
            // connection unusable, so the teardown opens its own.
            let _ = client.logout();
            let (mut client, _) = connect(&url, &sasl);

            for name in [&created, &renamed, &copied] {
                purge(&mut client, name, trash.as_ref());
            }

            client.logout().expect("LOGOUT");
        },
    );
}

/// The body of [`run_client`], everything that runs once the test
/// mailboxes exist. Split out so [`with_cleanup`] can own the teardown.
fn client_body(
    client: &mut ImapClientStd,
    url: &Url,
    sasl: &Sasl,
    capabilities: &[Capability<'static>],
    name: &str,
    copied: &str,
) {
    let has = |capability: Capability<'static>| capabilities.contains(&capability);

    client.subscribe(mailbox(name)).expect("SUBSCRIBE");
    let subscribed = client
        .lsub(mailbox(""), ListMailbox::try_from(name.to_owned()).unwrap())
        .expect("LSUB");
    assert!(!subscribed.is_empty(), "LSUB misses the subscribed {name}");
    client.unsubscribe(mailbox(name)).expect("UNSUBSCRIBE");

    let items = [StatusDataItemName::Messages, StatusDataItemName::UidNext];
    let status = client
        .status(mailbox(name), items.to_vec().into())
        .expect("STATUS");
    assert!(!status.is_empty(), "STATUS returned no item");

    // --- APPEND, buffered and streamed ---

    let opts = ImapMessageAppendOptions {
        flags: vec![Flag::Seen],
        ..Default::default()
    };
    let (_, appenduid) = client
        .append(mailbox(name), &build_message("buffered"), opts.clone())
        .expect("APPEND");
    if has(Capability::UidPlus) {
        assert!(appenduid.is_some(), "UIDPLUS advertised, no APPENDUID");
    }

    let message = build_message("streamed");
    client
        .append_stream(mailbox(name), message.as_slice(), message.len(), opts)
        .expect("APPEND (stream)");

    // --- watch (IDLE) on a second connection sees a third APPEND ---

    let (watcher, _) = connect(url, sasl);
    let watch_opts = ImapMailboxWatchStreamOptions {
        shutdown_poll: Duration::from_secs(1),
        ..Default::default()
    };
    let watch = watcher
        .watch_mailbox(mailbox(name), capabilities, watch_opts)
        .expect("watch mailbox");

    // NOTE: give the watcher time to select and enter IDLE, so the
    // APPEND below arrives as an unsolicited EXISTS.
    thread::sleep(Duration::from_secs(3));

    client
        .append(mailbox(name), &build_message("watched"), Default::default())
        .expect("APPEND (watched)");

    let event = watch
        .recv_timeout(Duration::from_secs(30))
        .expect("watch event before the deadline")
        .expect("watch event");
    assert!(
        matches!(event, ImapMailboxWatchEvent::EnvelopeAdded { .. }),
        "unexpected watch event {event:?}"
    );
    watch.close().expect("close watch");

    // --- EXAMINE, UNSELECT, SELECT, CHECK ---

    let examined = client
        .examine(mailbox(name), Default::default())
        .expect("EXAMINE");
    assert_eq!(examined.exists, Some(3), "EXAMINE count mismatch");

    if has(Capability::Unselect) {
        client.unselect().expect("UNSELECT");
    }

    client
        .select(mailbox(name), Default::default())
        .expect("SELECT");
    client.check().expect("CHECK");

    // --- SEARCH, FETCH, streamed FETCHes, SORT, THREAD ---

    let uid = ImapMessageSearchOptions { uid: true };
    let all = || Vec1::from(SearchKey::All);
    let uids = client.search(all(), uid.clone()).expect("UID SEARCH");
    assert_eq!(uids.len(), 3, "UID SEARCH count mismatch");
    let every = SequenceSet::try_from(uids.as_slice()).unwrap();

    let envelope =
        MacroOrMessageDataItemNames::MessageDataItemNames(vec![MessageDataItemName::Envelope]);
    let fetch_opts = ImapMessageFetchOptions {
        uid: true,
        ..Default::default()
    };
    let fetched = client
        .fetch(every.clone(), envelope, fetch_opts)
        .expect("UID FETCH");
    assert_eq!(fetched.len(), 3, "UID FETCH count mismatch");

    let mut body = Vec::new();
    client
        .fetch_body_stream(uids[0], true, &mut body)
        .expect("FETCH body (stream)");
    assert!(
        body.windows(SUBJECT.len()).any(|window| window == SUBJECT),
        "streamed body missing the subject"
    );

    let mut bodies = 0;
    client
        .fetch_bodies_stream(
            every.clone(),
            true,
            |_| Ok(Vec::new()),
            |_, body| {
                assert!(!body.is_empty(), "streamed batch body is empty");
                bodies += 1;
                Ok(())
            },
        )
        .expect("FETCH bodies (stream)");
    assert_eq!(bodies, 3, "streamed batch count mismatch");

    let by_date = Vec1::from(SortCriterion {
        reverse: true,
        key: SortKey::Date,
    });
    let sort_opts = ImapMessageSortOptions {
        uid: true,
        fallback: !capabilities
            .iter()
            .any(|capability| matches!(capability, Capability::Sort(_))),
    };
    let sorted = client.sort(by_date, all(), sort_opts).expect("SORT");
    assert_eq!(sorted.len(), 3, "SORT count mismatch");

    if capabilities
        .iter()
        .any(|capability| matches!(capability, Capability::Thread(_)))
    {
        let thread_opts = ImapMessageThreadOptions { uid: true };
        client
            .thread(ThreadingAlgorithm::OrderedSubject, all(), thread_opts)
            .expect("THREAD");
    }

    // --- STORE, COPY, MOVE, EXPUNGE ---

    let store_opts = ImapMessageStoreOptions { uid: true };
    client
        .store(
            every.clone(),
            StoreType::Add,
            vec![Flag::Flagged],
            store_opts.clone(),
        )
        .expect("UID STORE");

    // NOTE: the FETCH echo of a STORE is only a SHOULD (RFC 3501 section
    // 6.4.6), and Gmail skips it at times, so the flags are read back.
    let flagged = client
        .search(Vec1::from(SearchKey::Flagged), uid.clone())
        .expect("UID SEARCH FLAGGED");
    assert_eq!(flagged.len(), 3, "UID STORE did not flag every message");

    let first = SequenceSet::from(uids[0]);
    let second = SequenceSet::from(uids[1]);
    let third = SequenceSet::from(uids[2]);

    client
        .copy(first, mailbox(copied), ImapMessageCopyOptions { uid: true })
        .expect("UID COPY");

    if has(Capability::Move) {
        client
            .r#move(
                second,
                mailbox(copied),
                ImapMessageMoveOptions { uid: true },
            )
            .expect("UID MOVE");
    }

    client
        .store(
            third.clone(),
            StoreType::Add,
            vec![Flag::Deleted],
            store_opts.clone(),
        )
        .expect("UID STORE \\Deleted");

    if has(Capability::UidPlus) {
        client.uid_expunge(third).expect("UID EXPUNGE");
    }

    client.expunge().expect("EXPUNGE");
    client.close().expect("CLOSE");
}

/// Opens a session on `url`, authenticated with `sasl`.
fn connect(url: &Url, sasl: &Sasl) -> (ImapClientStd, Vec<Capability<'static>>) {
    let opts = ImapClientStdConnectOptions {
        sasl: Some(sasl.clone()),
        ..Default::default()
    };

    ImapClientStd::connect(url, opts).expect("connect")
}

/// Empties and deletes the mailbox `name`, best effort.
///
/// A provider mapping mailboxes to labels (Gmail) keeps the messages of
/// a deleted mailbox, so they are moved to the `\Trash` special-use
/// mailbox (RFC 6154) when there is one, and expunged from there.
fn purge(client: &mut ImapClientStd, name: &str, trash: Option<&Mailbox<'static>>) {
    if client.select(mailbox(name), Default::default()).is_err() {
        return;
    }

    let uid = ImapMessageSearchOptions { uid: true };
    let uids = client
        .search(Vec1::from(SearchKey::All), uid)
        .unwrap_or_default();

    if let Ok(set) = SequenceSet::try_from(uids.as_slice()) {
        let moved = trash.and_then(|trash| {
            let opts = ImapMessageMoveOptions { uid: true };
            client.r#move(set.clone(), trash.clone(), opts).ok()
        });

        match (trash, moved) {
            (Some(trash), Some(Some((_, _, trashed)))) => {
                let _ = client.select(trash.clone(), Default::default());
                expunge(client, &trashed);
            }
            _ => {
                let uids: Vec<u32> = uids.iter().map(|uid| uid.get()).collect();
                expunge(client, &uids);
            }
        }
    }

    let _ = client.close();

    if let Err(err) = client.delete(mailbox(name)) {
        eprintln!("WARNING: could not delete mailbox {name}, remove it by hand: {err}");
    }
}

/// Flags the given UIDs of the selected mailbox `\Deleted` and expunges
/// them, best effort.
fn expunge(client: &mut ImapClientStd, uids: &[u32]) {
    let Ok(set) = SequenceSet::try_from(uids) else {
        return;
    };

    let opts = ImapMessageStoreOptions { uid: true };
    let _ = client.store(set, StoreType::Add, vec![Flag::Deleted], opts);
    let _ = client.expunge();
}

/// Builds a small message carrying [`SUBJECT`].
fn build_message(part: &str) -> Vec<u8> {
    format!(
        "Date: Mon, 1 Jan 2024 00:00:00 +0000\r\n\
         From: io-imap <test@pimalaya.org>\r\n\
         To: io-imap <test@pimalaya.org>\r\n\
         Subject: io-imap integration test ({part})\r\n\
         \r\n\
         Hello from the io-imap integration test.\r\n"
    )
    .into_bytes()
}

/// Parses `name` as a mailbox.
fn mailbox(name: &str) -> Mailbox<'static> {
    Mailbox::try_from(name.to_owned()).expect("valid mailbox name")
}

/// A suffix unique to one run, dating a leftover an aborted run left
/// behind.
fn unique_suffix() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
}

/// Runs `body`, then `cleanup` whichever way `body` went, and only then
/// re-raises a panic `body` may have raised.
///
/// These flows run against real accounts, and every step panics on
/// failure: a cleanup written as the last statements of a flow would be
/// skipped the moment anything goes wrong. `cleanup` is caught too, so
/// a teardown that cannot reach the server reports it and never
/// replaces the failure the run was reporting.
fn with_cleanup<T, B, C>(state: &mut T, body: B, cleanup: C)
where
    B: FnOnce(&mut T),
    C: FnOnce(&mut T),
{
    let outcome = panic::catch_unwind(AssertUnwindSafe(|| body(state)));

    if panic::catch_unwind(AssertUnwindSafe(|| cleanup(state))).is_err() {
        eprintln!("WARNING: cleanup itself failed, the account may hold leftovers");
    }

    if let Err(payload) = outcome {
        panic::resume_unwind(payload);
    }
}
