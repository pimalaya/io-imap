---
cairn: change
id: only-what-enabled-lists-is-enabled
status: landed
created: 2026-11-15
---

# Only what ENABLED lists is enabled

## Why

`ImapMailboxWatch` sends `ENABLE CONDSTORE QRESYNC` when the server advertises QRESYNC, then takes the QRESYNC path on any tagged `OK`, whatever the untagged `ENABLED` said. RFC 5161 section 3.2 makes `ENABLED` the list of extensions "successfully enabled", and RFC 7162 section 3.2.3 requires QRESYNC enabled before the QRESYNC parameter of SELECT or EXAMINE. A server that answers `OK` without listing QRESYNC has not enabled it.

The live testing campaign of 2026-11-15 met such a server: it advertises QRESYNC in CAPABILITY, answers `ENABLE QRESYNC CONDSTORE` with a bare tagged `OK` and no `* ENABLED` line, and then answers `EXAMINE INBOX (QRESYNC (1 225))` with no FETCH although UID 12 has MODSEQ 227. The watch reads that as "nothing changed" and moves its resync point past the change, so arrivals, flag changes and expunges are lost for good, with IDLE or with polling.

## What

- The watch reads the list `ImapExtensionEnable` returns and takes the QRESYNC path only when it names QRESYNC, compared case-insensitively. A bare `OK`, or an `ENABLED` naming CONDSTORE alone, puts the watch on the existing whole-mailbox fallback: a plain `EXAMINE`, `UID FETCH 1:* (UID FLAGS)`, and a local diff on every wake. A resumed watch goes straight to that re-read.
- The ENABLE command itself does not change: it still asks for both, RFC 7162 section 3.2.3 requiring servers to accept `ENABLE QRESYNC CONDSTORE`.
- The other io-imap code touching these extensions was checked. `ImapExtensionEnable` already returns the `ENABLED` list and `None` without one; `ImapClient::enable` and `ImapClientAsync::enable` hand it back; the session opening ENABLEs nothing. `select_qresync` ENABLEs nothing either, it validates the capability slice its caller passes, so its docs now say QRESYNC must have been listed by ENABLE first.

## Scope / non-goals

- The watch has no CONDSTORE-only path (`CHANGEDSINCE`): CONDSTORE in `ENABLED` without QRESYNC counts as enabled but does not change the path.
- A resumed watch that falls back keeps the resync point it was given: the fallback never moves it, and a later QRESYNC resync from an older point reports a superset of the changes, which the shadow absorbs.
- No new error, yield or option: the fallback is a correct watch, only costlier, so the caller is not told.

## Decisions

- **Strict reading.** The previous code assumed some servers echo only CONDSTORE in `ENABLED` while honouring QRESYNC. Trusting an unlisted extension is what loses data; falling back only costs a whole-mailbox read per wake.
- Non-breaking, for a patch release: no signature, field or variant changes.
