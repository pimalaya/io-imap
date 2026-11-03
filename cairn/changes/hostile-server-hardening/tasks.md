---
cairn: tasks
change: hostile-server-hardening
---

# Tasks

- [ ] src/rfc3501/select.rs:196, :249-252: keep `VANISHED (EARLIER)` as ranges (or bound the expansion); adapt the output type and its callers
- [ ] A unit test feeding `* VANISHED (EARLIER) 1:4294967295` that completes without a large allocation
- [ ] src/send.rs:205: compare the tagged completion's tag with the sent command's; decide skip or fail on mismatch
- [ ] Carry the expected tag through `ImapSend::new` and `ImapSend::receive` for messages without one of their own
- [ ] A unit test where a foreign tagged completion arrives before the right one
- [ ] CHANGELOG under [Unreleased] (the select output type changes)
- [ ] Log; land
