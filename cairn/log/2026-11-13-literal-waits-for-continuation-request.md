---
cairn: log
change: literal-waits-for-continuation-request
landed: 2026-11-13
---

# A synchronising literal waits for its continuation request

src/send.rs released a parked synchronising literal as soon as the buffered server bytes were used up and the exchange was not done, without looking at the continuation request it had recorded. The literal therefore went out after a complete untagged line, a completion of another command, or the first part of any line, a tagged `NO` refusing the command included, against RFC 3501 sections 4.3 and 7.5. A refused APPEND could send its message to a server reading command lines, and a continuation request split across two reads ended the exchange without its tagged completion (`MissingTagged` on a stored message). Found by the family audit of 2026-11-13 (IMAPA-01 and IMAPB-03, one defect).

The release now takes the decoded continuation request and goes back to reading when there is none, so one request releases one literal. A whole tagged `NO` or a BYE read in place of the request ends the exchange as before, the literal unsent. `ImapSendOutput::continuation_request` no longer carries the request that released a literal; no coroutine read it there (the SASL and IDLE exchanges that do read it park no literal). The streamed APPEND was not concerned: it waits for its continuation request through `ImapSend::receive`.

Capabilities moved: coroutines (requirement "A synchronising literal waits for its continuation request" added).

Verified: `send::tests::sync_literal_waits_through_untagged_line`, `sync_literal_waits_through_split_continuation_request` and `sync_literal_stays_unsent_on_split_no` fail against the previous release arm (each on its first read, which yielded the literal instead of `WantsRead`) and pass; `rfc3501::append::tests::tagged_no_returns_no_error` (a whole `NO` in one read) passes unchanged; `cargo test --all-features` passed (265 unit, 11 integration, 47 doc tests); `cargo clippy --all-features --all-targets -- -D warnings` clean but for the pre-existing one-element range array in src/watch.rs; `cargo build --no-default-features` builds.

Left open: the fuzz targets send no command holding a literal, so the rule "no literal octet before a continuation request" has no fuzz oracle yet.
