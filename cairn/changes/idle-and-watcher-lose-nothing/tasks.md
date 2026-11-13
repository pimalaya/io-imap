---
cairn: tasks
change: idle-and-watcher-lose-nothing
---

# Tasks

- [x] src/client.rs: `set_stream` empties the fragmentizer in place (`client::tests::set_stream_keeps_the_configured_message_size`)
- [x] src/rfc2177/idle.rs: the read state takes its argument before testing `done` and the timer (`idle::tests::bytes_read_once_done_is_set_yield_event`)
- [x] src/rfc2177/idle.rs: the data of the DONE exchange is yielded as an event before completing or re-idling (`data_read_before_done_completion_yields_event`, `data_read_before_refresh_completion_yields_event`)
- [x] src/rfc2177/idle.rs: BYE while idling is `ImapIdleError::Bye`, an undecodable untagged line is skipped, no empty event (`bye_while_idling_returns_bye_error`, `undecodable_untagged_line_is_skipped`, `read_completing_no_response_yields_no_event`)
- [x] src/watch.rs: the watch wakes on mailbox data only (`watch::tests::a_keepalive_does_not_wake_the_watch`), and resyncs on data read during a refresh (`data_read_while_an_idle_is_refreshed_wakes_the_watch`)
- [x] src/watch.rs: the baseline is `UID FETCH 1:* (UID FLAGS)` (`the_baseline_is_fetched_by_uid`)
- [x] src/watch.rs: `ImapMailboxWatchState`, `ImapMailboxWatch::state`, `ImapMailboxWatchOptions::resume_from` (`the_state_follows_the_baseline`, `a_resumed_fallback_watch_emits_what_changed_meanwhile`, `a_resumed_qresync_watch_starts_at_the_resync`)
- [x] src/client.rs: the watch stream drops its receiver before joining (`client::tests::closing_a_watch_stream_nobody_drains_returns`), `into_state`, `ImapMailboxWatchStreamOptions::resume_from`
- [x] CHANGELOG under [Unreleased]
- [x] Fold the delta into cairn/spec, log, land
