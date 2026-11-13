---
cairn: log
change: idle-and-watcher-lose-nothing
landed: 2026-11-13
---

# IDLE and the watcher lose nothing

Six findings of the family audit of 2026-11-13 on IDLE and the mailbox watcher, and one follow-up.

- **Follow-up to exchanges-end-on-their-own-tag.** `ImapClientStd::set_stream` built a fragmentizer of the default size, losing one a caller had configured. imap-codec exposes no getter for the limit, so the fragmentizer is emptied in place instead: `progress` is run until it has taken every buffered byte, then `skip_message` drops the message in flight and resets the parser.
- **IDLE read order (IMAPB-01).** The read state of `ImapIdle` takes its argument, drains the fragmentizer and yields what was collected before it looks at `done` and the timer; the DONE follows on the next resume. Bytes of an unfinished line now stay in the fragmentizer, where the DONE exchange completes and collects them. The timer itself is untouched (IMAPB-12 waits for a decision).
- **Data of the DONE exchange (IMAPB-06).** Two states follow DONE: `Finish`, and `Refresh` when the timer had run out. The data and untagged status of the DONE exchange are yielded as an event first. `Refresh` re-issues IDLE unless `done` was set meanwhile, which is what the watcher does on that event: it completes, and the watcher resyncs, without the extra IDLE and DONE round trip the previous flow would have cost.
- **IDLE against `ImapSend` (IMAPB-16).** A BYE while idling fails with `ImapIdleError::Bye` (the `bye` field nothing read is gone); an undecodable untagged line is skipped, and a tagged line that only decodes lossily is ignored like any tagged line there; a read completing no response yields nothing. The watcher sets `idle_saw_data` only for EXISTS, EXPUNGE, FETCH or VANISHED, so a keepalive no longer costs a DONE, an EXAMINE and a mailbox read.
- **Baseline by UID (IMAPB-10).** `fetch_uid_flags` sends `UID FETCH 1:* (UID FLAGS)`. No server was tried: the reading of RFC 3501 section 9 stands as the audit left it, and the UID form is valid either way.
- **Resume (IMAPB-18).** `ImapMailboxWatchState` holds the UIDVALIDITY, the resync point and the flags by UID. `ImapMailboxWatch::state` returns it once the baseline is seeded (a new `seeded` flag, since the UIDVALIDITY is known one step earlier), and `ImapMailboxWatchOptions::resume_from` starts a watch from it: straight at `ExamineResync` without QRESYNC, at `ExamineQresync` after ENABLE with it. The existing UIDVALIDITY check ends a resume on a recreated mailbox. The shadow moves ahead of the events while some are still queued, so the state is exact once the watch has ended, which is when a caller needs it. For the blocking client the worker returns the state through its join handle, `ImapMailboxWatchStream::into_state` hands it out and `ImapMailboxWatchStreamOptions::resume_from` takes it back. Both options structs lose `Copy`.
- **Close on a full channel (IMAPA-21).** The stream holds its receiver in an `Option` and drops it before joining, in one private `stop` used by `close`, `into_state` and `Drop`.

Breaking: `ImapMailboxWatchOptions` and `ImapMailboxWatchStreamOptions` are no longer `Copy` and gain a field. `ImapIdle` no longer yields empty events.

Left open: examples/tokio_watch.rs never resumes on the timer, so its IDLE is not refreshed (with IMAPB-12); a tagged line read while idling is ignored whatever its tag; the `HIGHESTMODSEQ 0` and shutdown-without-DONE traps of the watcher.

Capabilities moved: mailbox-watch (new spec file), std-client (stream swap modified, watch stream close added).

Verified: each test of a fixed behaviour failed first (`set_stream_keeps_the_configured_message_size`: limit not exceeded; `bytes_read_once_done_is_set_yield_event`: got `WantsWrite(DONE)`; `data_read_before_done_completion_yields_event`: got `Complete(Ok)`; `data_read_before_refresh_completion_yields_event`: got `WantsTag`; `bye_while_idling_returns_bye_error` and `read_completing_no_response_yields_no_event`: got an empty event; `undecodable_untagged_line_is_skipped`: got `DecodingFailure`; `a_keepalive_does_not_wake_the_watch`: `DONE` written; `the_baseline_is_fetched_by_uid`: wrote `A2 FETCH 1:* (UID FLAGS)`; `closing_a_watch_stream_nobody_drains_returns`: close still waiting after 2 seconds). The resume tests and `data_read_while_an_idle_is_refreshed_wakes_the_watch` cover new code and had no red run. `cargo test --all-features` passed (305 unit, 11 integration, 47 doc tests); `cargo clippy --all-features --all-targets -- -D warnings` clean; `cargo build --no-default-features` builds; `cargo doc` has no broken link.
