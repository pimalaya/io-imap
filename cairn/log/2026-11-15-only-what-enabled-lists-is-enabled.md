---
cairn: log
change: only-what-enabled-lists-is-enabled
landed: 2026-11-15
---

# Only what ENABLED lists is enabled

Found by the live testing campaign of 2026-11-15 on iCloud (imap.mail.me.com): CAPABILITY lists QRESYNC, `ENABLE QRESYNC CONDSTORE` is answered by a bare tagged `OK` with no `* ENABLED`, and `EXAMINE INBOX (QRESYNC (1 225))` then returns no FETCH although UID 12 has MODSEQ 227. io-imap 0.11.1's watch took any `OK` as QRESYNC enabled, so each resync read nothing and moved `highest_mod_seq` past the change; carillon's `watch` never reported an arriving message there, with IDLE or polling. Reproduced read-only; the fix was tested on fakes only.

On completion of its ENABLE, `ImapMailboxWatch` now sets its `qresync` flag from the list `ImapExtensionEnable` returns: true only when it names QRESYNC, compared case-insensitively through the capability's display form (QRESYNC has no typed variant in imap-types). Otherwise the watch takes the existing whole-mailbox fallback: a new watch sends a plain `EXAMINE` (no `CONDSTORE` parameter) before its `UID FETCH 1:* (UID FLAGS)` baseline, a resumed one goes straight to the plain re-read, and every wake re-reads and diffs. CONDSTORE listed alone does not open the QRESYNC path, the watch having no CONDSTORE-only path. The ENABLE command still asks for both; the NOTE that justified it by servers echoing only CONDSTORE now cites RFC 7162 section 3.2.3 instead. A resumed watch that falls back keeps the resync point it was given, which only makes a later QRESYNC resume ask from an older point.

Checked for the same assumption elsewhere in io-imap: `ImapExtensionEnable` already returned the `ENABLED` list (`None` without one), `ImapClient::enable` and `ImapClientAsync::enable` hand it back, and the session opening ENABLEs nothing. `select_qresync` ENABLEs nothing and checks only the capability slice its caller passes, so its docs (both traits) now say QRESYNC must be listed by `enable` first. The module and crate docs name the new fallback trigger.

Non-breaking: no signature, field or variant change.

Capabilities moved: mailbox-watch (one requirement added, the QRESYNC resume scenario modified to name its `ENABLED`).

Verified: `watch::tests::an_enable_not_listing_qresync_falls_back_to_the_whole_mailbox` (bare `OK` and `* ENABLED CONDSTORE`) failed on 0.11.1 with `wrote A2 EXAMINE INBOX (CONDSTORE)`, and `a_resumed_watch_whose_enable_omits_qresync_re_reads_the_whole_mailbox` with `wrote A2 EXAMINE INBOX (QRESYNC (1700 225))`, the wire line of the live run. Both pass with the fix. `cargo test --all-features` passed (356 unit, 12 integration, 47 doc tests, 10 live tests ignored); `cargo clippy --all-features` and `--all-targets` with `-D warnings` clean; `cargo build --no-default-features` builds; `cargo doc` has no broken link.
