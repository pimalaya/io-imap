---
cairn: change
id: idle-and-watcher-lose-nothing
status: landed
created: 2026-11-13
---

# IDLE and the watcher lose nothing

## Why

Six findings of the family audit of 2026-11-13 on the IDLE coroutine, the mailbox watcher and its blocking stream, each re-checked against the code the same day, and one follow-up to the change exchanges-end-on-their-own-tag.

- **IDLE drops the bytes it is resumed with (IMAPB-01).** In its read state `ImapIdle` tested `done` and its refresh timer before taking its argument. When either was due, it built the DONE send and handed it the bytes, which a send about to write never reads. A notification arriving with the wakeup that found the timer expired was lost: no event, no resync, until some later change woke the watcher. A read ending inside a line left its tail to fail the DONE exchange as `DecodingFailure`.
- **Data read while DONE completes is dropped (IMAPB-06).** The DONE exchange collected untagged responses up to the tagged OK, and only its BYE and status were looked at. On a timer refresh the coroutine re-idled by itself, so a message delivered during that round trip, every 29 seconds, went unreported.
- **IDLE and `ImapSend` disagree (IMAPB-16).** While idling, a BYE was stored in a field nothing read, so it surfaced as an empty event and then `Eof`; an untagged line imap-codec cannot decode ended the watch, where a send skips it; and an event was yielded on every read, even one completing no line, each waking the watcher into a DONE, an EXAMINE and, without QRESYNC, a read of the whole mailbox for a server keepalive.
- **The baseline `FETCH 1:*` is by sequence number (IMAPB-10).** RFC 3501 section 9 has a server answer BAD to `*` as a sequence number on an empty mailbox; as a UID it is always valid.
- **A watch cannot resume (IMAPB-18).** After a disconnect the caller built a new watch, whose baseline silently took in whatever changed during the outage. The UIDVALIDITY, resync point and shadow were private.
- **Closing a watch stream can hang (IMAPA-21).** The worker forwards events with a blocking send on a bounded channel; `close` and `drop` joined it while still holding the receiver, so a worker parked on a full channel never returned.
- **Follow-up: `set_stream` loses a custom message size.** It replaced the fragmentizer with one of the default size.

IMAPB-12, the clock and the shared flag inside the IDLE coroutine, is left for a maintainer decision: the timer stays where it is.

## What

- `ImapIdle` takes its argument first, drains the fragmentizer, yields an event when a response was collected, and only then tests `done` and the timer. It fails with `ImapIdleError::Bye` on a BYE, skips an undecodable untagged line, and yields no empty event. After DONE completes it yields the data of that exchange as an event, then either completes or, on a timer refresh, re-issues IDLE unless `done` was set meanwhile.
- The watcher wakes on mailbox data only (EXISTS, EXPUNGE, FETCH, VANISHED), fetches its baseline with `UID FETCH 1:* (UID FLAGS)`, exposes `state()` (the new `ImapMailboxWatchState`: UIDVALIDITY, resync point, flags by UID) and takes one back through `ImapMailboxWatchOptions::resume_from`, starting at the resync step.
- `ImapMailboxWatchStream` drops its receiver before joining the worker, and gains `into_state()`; `ImapMailboxWatchStreamOptions::resume_from` carries a state to the worker.
- `ImapClientStd::set_stream` empties the fragmentizer in place, which keeps its size limit.

## Limits

- examples/tokio_watch.rs still resumes only on data or shutdown, so its IDLE is never refreshed by the timer. This belongs with IMAPB-12.
- A tagged line read while idling is still ignored, whatever its tag.
- The two open traps of the watcher are untouched: a mailbox reporting `HIGHESTMODSEQ 0`, and the blocking worker returning on shutdown without sending DONE.
