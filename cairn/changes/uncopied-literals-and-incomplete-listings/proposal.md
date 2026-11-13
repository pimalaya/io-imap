---
cairn: change
id: uncopied-literals-and-incomplete-listings
status: landed
created: 2026-11-13
---

# Uncopied literals and incomplete listings

## Why

A follow-up of authenticate-cancellation-and-command-outputs, then findings of the family audit of 2026-11-13, each re-checked against the code the same day.

- **The watch reads an incomplete listing as complete.** A message whose FETCH line was skipped for not decoding was missing from the whole-mailbox snapshot, so the watch reported it removed. On the QRESYNC path a skipped line was lost for good, the resync point moving past it.
- **A buffered payload is copied three times (IMAPA-11, IMAPB-13).** A send kept the encoded command for an echo no coroutine read, the encoder copied its literal into a fragment, and the fragment was copied behind the command line into the write buffer: a buffered APPEND of 8 MiB added a peak of 24 MiB. The streamed APPEND cloned its command for the same echo. An error of the fragmentizer carried the whole message, up to its cap. The buffered FETCH built its map twice, and the watch cloned every changed item list.
- **A write prints its bytes (IMAPA-18).** `ImapYield` derived `Debug` over `WantsWrite(Vec<u8>)`, so a caller logging a yield logged the encoded LOGIN or AUTHENTICATE. The crate header promised that secrets never land in logs.
- **URL errors print the URL (IMAPA-17).** The two errors of `ImapSessionTransport::from_url` held and displayed the whole URL, userinfo and query included.
- **An empty SCRAM nonce is accepted (IMAPA-15).** Only `ImapClientStd::connect` drew a nonce for credentials left without one. The coroutine sent `r=` empty, and any server nonce extends an empty one.
- **`scram` pulls std (IMAPA-07).** The feature enabled rand with its default features, though the only use of rand is in the connect module, which the TLS features gate.
- **Five comments disagree with the code (IMAPA-19).**

## What

- The watch keeps its shadow, and removes nothing, when the snapshot of a re-read skipped a line; it keeps its resync point when a QRESYNC reply did.
- `ImapSend` drops the command once encoded and yields each literal as the payload of a write of its own. `ImapSendOutput::message` is removed, which leaves `ImapSendOutput` and `ImapSendResult` without a type parameter, and `ImapSend::receive` takes the tag alone.
- The errors carrying a response (`DecodingFailure`, `MessageIsPoisoned`, `MessageTooLong` of the send, the greeting and IDLE) carry its first 1024 octets.
- The buffered FETCH builds one map; `compute_deltas` takes the select data by value; APPEND and APPENDUID trace their command name.
- `Debug` is written by hand for `ImapYield` and `ImapSessionOpenYield`: a write prints its length.
- The URL errors hold the scheme, host and port.
- `ImapAuthScramSha256::new` returns a `Result` and fails with `EmptyNonce`.
- `scram = ["io-sasl/scram"]`; the three TLS features list `dep:rand`, declared with `default-features = false, features = ["thread_rng"]`.
- The five comments are corrected.

## Not done

- `ImapClient::append` still copies the slice it is given: its signature takes `&[u8]`.
- The encoder of imap-codec copies the literal into its fragment: one copy remains.
- The fragmentizer keeps the capacity of its largest message for the life of the connection: imap-codec's.
- The yields of the watch, IDLE, the streamed APPEND and the FETCH streams still derive `Debug`: their writes carry no credentials, their body chunks carry message content.
- The `saslprep` feature of io-sasl is not enabled: a behaviour change that waits for the maintainer.
