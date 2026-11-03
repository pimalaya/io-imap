---
cairn: log
change: hostile-server-hardening
landed: 2026-11-03
---

# A hostile server cannot exhaust memory or end the wrong wait

- `ImapSend` ends only on the tagged completion of its own command and skips any other, logging it at debug. `command` records the tag the caller answered `WantsTag` with; `new` and `receive` now take the expected tag, which the SASL continuations and IDLE DONE get from the exchange they continue through the new `ImapSendOutput::tag`. Skipping rather than failing keeps a session alive through the late completion of an abandoned command.
- `ImapMailboxSelectData::vanished_earlier` holds inclusive UID ranges. SELECT and EXAMINE (which carried a second copy of the expansion) share `select::uid_ranges`, and the watch removes the shadowed UIDs within each range, so the cost follows the shadow size rather than the span a server announces.
- `tests/rfc3501.rs` canned replies are tagged `A001`; they passed before only because any tagged line ended an exchange, and now answer `WantsTag` with that tag.

Capabilities moved: `coroutines` (tag matching added), `mailbox-select` (new spec file).
