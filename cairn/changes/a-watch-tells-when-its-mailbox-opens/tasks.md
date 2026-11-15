---
cairn: tasks
change: a-watch-tells-when-its-mailbox-opens
---

# Tasks

- [x] src/watch.rs: `ImapMailboxWatch::opened`, set by the initial, QRESYNC and resync EXAMINE once their checks pass (`watch::tests::the_watch_opens_once_its_examine_succeeds`, `a_qresync_watch_opens_on_its_examine_not_its_enable`, `a_resumed_watch_opens_once_its_resync_examine_succeeds`, `a_refused_examine_never_opens_the_watch`, `a_recreated_mailbox_never_opens_a_resumed_watch`)
- [x] src/client.rs: the worker signals the opening before what the resume yielded; `ImapMailboxWatchStream::opened` and `wait_opened` (`client::tests::a_watch_stream_opens_once_its_examine_succeeds`, `a_watch_stream_refused_its_examine_never_opens`)
- [x] CHANGELOG under [Unreleased]
- [x] Fold the delta into cairn/spec, log, land
