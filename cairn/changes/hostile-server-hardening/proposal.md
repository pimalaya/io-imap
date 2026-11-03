---
cairn: change
id: hostile-server-hardening
status: landed
created: 2026-10-18
---

# A hostile server cannot exhaust memory or end the wrong wait

## Why

Two places where the client trusts the server more than it should, each re-checked against the code on 2026-10-18.

- **Unbounded UID set expansion.** src/rfc3501/select.rs:249-252 `expand_uid_set` expands a `VANISHED (EARLIER)` uid-set into concrete UIDs with `u32::MAX` as ceiling, called from select.rs:196. A single `* VANISHED (EARLIER) 1:4294967295` from a hostile or buggy server makes the client allocate about four billion `NonZeroU32` (16 GiB) and abort.
- **Tagged completion not matched to its command (audit item S3-10).** src/send.rs:205-207 takes the first `Status::Tagged` it decodes as the end of the exchange without comparing its tag to the command's. A completion meant for another command, or a forged one, ends the wait early and its status (OK, NO, BAD) is attributed to the wrong command.

## What

- `vanished_earlier` keeps ranges (the `SequenceSet` or a list of `RangeInclusive<NonZeroU32>`) rather than expanded UIDs, or the expansion stops at a documented bound and fails the select past it. Keeping ranges is the stronger fix, since any bound is still a server-chosen allocation.
- `ImapSend` remembers the tag of the command it sent and ends only on a tagged completion carrying that tag; a mismatching one is logged and skipped (or fails the exchange, to decide). `ImapSend<T: Encoder>` is generic and some messages carry no tag (`receive` for the streamed APPEND literal, IDLE DONE, AUTHENTICATE continuations), so the expected tag is passed in or taken from the message where it has one.

The crate has no spec yet, so there is no delta; a spec for the send coroutine and SELECT could be started with this change.
