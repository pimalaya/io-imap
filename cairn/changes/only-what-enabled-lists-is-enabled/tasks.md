---
cairn: tasks
change: only-what-enabled-lists-is-enabled
---

# Tasks

- [x] src/watch.rs: regression tests failing on 0.11.1, a new watch and a resumed watch whose ENABLE does not list QRESYNC (`watch::tests::an_enable_not_listing_qresync_falls_back_to_the_whole_mailbox`, `a_resumed_watch_whose_enable_omits_qresync_re_reads_the_whole_mailbox`)
- [x] src/watch.rs: the QRESYNC path only when `ENABLED` names QRESYNC, the whole-mailbox fallback otherwise
- [x] src/client.rs: `select_qresync` docs name the ENABLE precondition
- [x] Check every other place ENABLEing QRESYNC or CONDSTORE: none in io-imap besides the watch
- [x] CHANGELOG under [Unreleased]
- [x] Fold the delta into cairn/spec, log, land
