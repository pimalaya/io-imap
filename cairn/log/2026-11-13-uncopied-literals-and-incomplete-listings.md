---
cairn: log
change: uncopied-literals-and-incomplete-listings
landed: 2026-11-13
---

# Uncopied literals and incomplete listings

A follow-up of authenticate-cancellation-and-command-outputs and seven findings of the family audit of 2026-11-13.

- **Incomplete listings.** Neither the watch spec nor the maintainer's notes chose between failing the resync and keeping the shadow. Keeping it won: failing would end the watch for good on a mailbox holding one line the codec cannot read, which is what skipping such lines was introduced to avoid (pimalaya/himalaya#641). A whole-mailbox snapshot that skipped a line removes nothing: additions and flag changes still flow, a removal waits for a complete re-read. A QRESYNC reply that skipped a line is applied, its deltas being idempotent against the shadow, and its resync point is kept, so the server reports the same changes again.
- **Payload copies (IMAPA-11, IMAPB-13).** `ImapSend` no longer keeps the command: it is dropped once encoded, and `ImapSendOutput::message` is gone with the type parameter it gave `ImapSendOutput` and `ImapSendResult`. Each literal is the payload of a write of its own. Moving the parked literal into the write buffer and appending the line end, as first suggested, would have doubled the capacity of that buffer on the first `extend`; yielding the literal alone costs nothing, at the price of one more write per literal (three for an APPEND: line, literal, line end). Counted by an allocator in tests/append_peak.rs, a buffered APPEND of 8 MiB adds a peak of 8 MiB where it added 24: the copy left is the encoder's. The errors holding a response carry its first 1024 octets. The buffered FETCH builds its map once, the watch takes the select data by value, APPEND and APPENDUID no longer format their message for a trace line.
- **Debug of a write (IMAPA-18).** Written by hand for `ImapYield`, and for `ImapSessionOpenYield`, which forwards the same LOGIN and AUTHENTICATE writes. The header of the crate no longer claims that secrets never land in logs: imap-types redacts a `Secret` in release builds only.
- **URL errors (IMAPA-17).** They hold what `url_location` builds: scheme, host and port.
- **Empty nonce (IMAPA-15).** `ImapAuthScramSha256::new` returns a `Result`. The client method left the generated list, a fallible constructor needing the boxed future `login` already uses in the async trait.
- **rand (IMAPA-07).** `cargo tree --no-default-features --features scram -e features,no-dev` listed rand with `std`, `std_rng`, `sys_rng` and `thread_rng` before, and lists no rand after.
- **Comments (IMAPA-19).** lib.rs on the State enums and on the size of the connect pump, login.rs on what an AString refuses (checked: a line break goes out as a literal), raw.rs on a cap it does not mirror, client.rs on what an empty read does.
- `ImapClientError::is_connection_lost` also sees the `Eof` of an IDLE and the `ShortBody` of the FETCH streams, missed by the previous change.

Breaking: `ImapSendOutput::message` removed; `ImapSendOutput` and `ImapSendResult` no longer generic; `ImapSend::receive` takes the tag alone; a literal is a write of its own; the response errors of the send, the greeting and IDLE hold 1024 octets at most; `ImapAuthScramSha256::new` returns a `Result`; the URL errors hold scheme, host and port; `scram` no longer enables rand.

Existing tests changed, all for the writes a literal now takes: `send::tests::sync_literal_waits_through_untagged_line` and `sync_literal_waits_through_split_continuation_request`, `append::tests::sync_success_with_appenduid_returns_pair` and `non_sync_sends_body_inline` (renamed `non_sync_sends_body_without_waiting`), the four tests of appenduid. The SCRAM tests unwrap the constructor.

Capabilities moved: coroutines (five requirements added, one modified), mailbox-watch (one requirement added).

Verified: `a_listing_that_skipped_a_line_removes_nothing` failed with `got [EnvelopeRemoved { uid: 1 }, FlagsAdded { uid: 2, flags: [Seen] }]`, `a_qresync_reply_that_skipped_a_line_keeps_the_resync_point` with a resync point of 50, the peak test with `a message of 8388608 octets added a peak of 25165980 octets`, the two Debug tests of `coroutine` with the bytes of the write, the URL test with the whole URL, `empty_nonce_is_refused`, in a first form resuming the coroutine, with `expected Complete(Err), got Yielded(WantsWrite(31 octets))`, and the error test with the 64 KiB line once the bound was lifted. The Debug test of the session yield was not run against the derive. `cargo test --all-features` passed (330 unit, 12 integration, 47 doc tests); `cargo clippy --all-features --all-targets -- -D warnings` clean; `cargo build --no-default-features` builds, as do `scram` alone, `client` alone and a TLS feature without `scram`.
