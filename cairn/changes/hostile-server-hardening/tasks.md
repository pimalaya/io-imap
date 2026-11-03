---
cairn: tasks
change: hostile-server-hardening
---

# Tasks

- [x] src/rfc3501/select.rs:196, :249-252: `VANISHED (EARLIER)` kept as `RangeInclusive<NonZeroU32>` (`uid_ranges`); src/rfc3501/examine.rs, which had its own expansion, reuses it; src/watch.rs walks its shadow within each range
- [x] A unit test feeding `* VANISHED (EARLIER) 1:4294967295` (`select::tests::vanished_earlier_keeps_ranges`, plus `watch::tests::vanished_range_removes_only_shadowed_uids`)
- [x] src/send.rs: the tagged completion's tag is compared with the expected one; a mismatch is skipped (a late completion of an abandoned command is legitimate, so failing would break the session)
- [x] The expected tag: `ImapSend::command` records the tag it is answered with; `ImapSend::new` and `ImapSend::receive` take it (SASL continuations and IDLE DONE pass the tag of the command they continue, through the new `ImapSendOutput::tag`)
- [x] A unit test where a foreign tagged completion arrives before the right one (`send::tests::foreign_tagged_completion_is_skipped`, fails without the guard)
- [x] CHANGELOG under [Unreleased]
- [x] Log; land
