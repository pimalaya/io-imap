---
cairn: tasks
change: literal-waits-for-continuation-request
---

# Tasks

- [x] Unit tests in src/send.rs failing against the previous code: an untagged line before the continuation request (`send::tests::sync_literal_waits_through_untagged_line`), a continuation request split across two reads (`send::tests::sync_literal_waits_through_split_continuation_request`), a tagged `NO` split across two reads (`send::tests::sync_literal_stays_unsent_on_split_no`)
- [x] src/send.rs: the parked literal is released only by taking a decoded continuation request, otherwise the send reads again
- [x] The whole `NO` in one read still ends the exchange (`rfc3501::append::tests::tagged_no_returns_no_error`, unchanged)
- [x] CHANGELOG under [Unreleased]
- [x] Fold the delta into cairn/spec/coroutines.md, log, land
