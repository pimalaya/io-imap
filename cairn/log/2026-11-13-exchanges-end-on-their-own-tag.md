---
cairn: log
change: exchanges-end-on-their-own-tag
landed: 2026-11-13
---

# Exchanges end on their own tag and leave no bytes behind

Seven findings of the family audit of 2026-11-13 on where an exchange ends and what it leaves on the connection.

- **Stream completions (IMAPB-04).** `ImapMessageFetchStream` and `ImapMessageFetchStreamBatch` keep the tag they were answered with and end through the new crate-private `send::decode_completion`, which gives the tagged completion of that tag or a BYE, skips any other tag, and reads a completion whose text holds 8-bit bytes through `send::decode_lossy_tagged` (the former `ImapSend::lossy_completion`, now without its tag check). A stale `B9 OK` used to end the single stream with an empty sink, which callers read as a missing message. The two stream files share that decoder; each still has its own copy of the line reader, left alone because it is not part of the defect.
- **Bytes past the completion (IMAPB-15).** On their completion or BYE the streams give their unread `pending` bytes to the fragmentizer, where `ImapSend` already leaves its own leftovers. They are parsed with the next read: a send asks for a read before looking at what the fragmentizer holds.
- **Foreign 8-bit completion (IMAPA-S1).** `ImapSend` compares the tag after the lossy decode instead of inside it, so a late `B9 NO ... Été` is skipped like its ASCII form instead of failing the running command with `DecodingFailure`.
- **LOGOUT and BYE (IMAPA-06).** `ImapSend::command` notes a `CommandBody::Logout`: for that command a BYE does not set `done`, and the end of the stream after the BYE completes the exchange with the BYE alone. `ImapLogout` returns `Ok` in that case, which made `ImapLogoutError::MissingTagged` unreachable: it is removed. Every other command still ends on a BYE at once, so the typed `Bye` errors keep the server's text. The flag is read off the command rather than set by the LOGOUT coroutine so a LOGOUT sent through `ImapSend::command` cannot miss it. With `ImapClientStd`, a server closing after its BYE without the completion still surfaces as `Io(UnexpectedEof)`, the client turning an empty read into an error before the coroutine sees it.
- **FETCH attribution (IMAPB-07).** `ImapMessageFetchFirst` keeps its id and merges only the FETCH responses for it: `seq == id`, or a `UID id` item in UID mode, which RFC 3501 section 6.4.8 makes every response to a UID command carry. A server leaving the UID out of a UID FETCH response now gets `MissingData`. The SORT fallback keeps the set of ids its SEARCH returned and drops any other from the sorted result. Not done, on purpose: `ImapMessageFetch` and `ImapMessageStore` still key by sequence number in UID mode and keep unsolicited FETCH data (changing the key is an API decision), and STATUS still takes any `STATUS` line (comparing mailbox names risks dropping the answer of a server that normalises them).
- **Flush (IMAPA-16).** `flush` follows each `write_all` in `ImapClientStd::run`, `fetch_body_stream`, `fetch_bodies_stream`, `append_stream`, the watch worker and `connect`.
- **Stream swap (IMAPA-20).** `ImapClientStd::set_stream` replaces the fragmentizer with a new one of the default size. The optional STARTTLS entry point for a connection whose greeting was already read was not added.

Also: the one-element range array in a test of src/watch.rs is bound to a local first, so `cargo clippy -- -D warnings` is clean without an allowance.

Breaking: `ImapLogoutError::MissingTagged` removed. No signature changes.

Capabilities moved: coroutines (two requirements modified, two added), message-sort (searched ids added), message-fetch and std-client (new spec files).

Verified: each new test failed against the previous code (`a_foreign_completion_holding_8bit_text_is_skipped` got an error instead of `WantsRead`; `bye_and_completion_in_two_reads_return_ok` got `Complete(Err(MissingTagged))`; the stream tests got `Complete(Ok(()))` on the foreign `OK`, `WantsRead` on the 8-bit `NO` and an empty fragmentizer; `first_skips_fetch_of_another_message` got the other message's `FLAGS`; the SORT fallback returned `[3, 2, 1]`; `commands_are_flushed_before_reading` got `Io(UnexpectedEof)`; `set_stream_forgets_bytes_of_the_previous_stream` got the stale bytes in front). `bye_then_eof_returns_ok` exercises a path that did not exist. `cargo test --all-features` passed (291 unit, 11 integration, 47 doc tests); `cargo clippy --all-features --all-targets -- -D warnings` clean; `cargo build --no-default-features` builds; `cargo doc` has no broken link. Both fuzz targets ran 20 seconds each (122,203 and 177,964 runs) without a crash.
