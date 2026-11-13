---
cairn: log
change: list-pattern-wire-form
landed: 2026-11-12
---

# LIST and LSUB patterns go out encoded and quoted

`ImapMailboxList::new` and `ImapMailboxLsub::new` encoded the reference to modified UTF-7 (RFC 3501 section 5.1.3) but sent the pattern as given, so a non-ASCII pattern went out as a raw UTF-8 literal and matched nothing: himalaya's live tests of 2026-11-12 listed nothing for `Himalaya-Test-FM-Été` on Fastmail. The new `rfc3501::mailbox::encode_list_inplace` encodes the pattern, the `*` and `%` wildcards being ASCII and passing through, then sends it as a quoted string when it fits one. Quoting also makes LSUB work on iCloud, which answers `BAD Parse Error` to a pattern sent as a bare `list-char` token (`LSUB "" Himalaya-Test-IC*`) and accepts it quoted; every server must read the quoted form.

Capabilities moved: none (no spec file covers LIST).

Verified: `encode_list_inplace_encodes_and_quotes_the_pattern`; `cargo test --all-features` passed; clippy clean but for the pre-existing src/watch.rs warning. Live through himalaya: `imap list -A -p 'Himalaya-Test-FM-Été'` lists the mailbox on Fastmail, `imap list -p 'Himalaya-Test-IC*'` (LSUB) and `imap list -A -p 'Himalaya-Test-IC-Ét*'` list on iCloud.
