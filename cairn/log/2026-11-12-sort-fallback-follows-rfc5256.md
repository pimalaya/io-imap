---
cairn: log
change: sort-fallback-follows-rfc5256
landed: 2026-11-12
---

# The client-side sort follows RFC 5256

Himalaya's live tests of 2026-11-12 ran the SORT fallback against iCloud, whose server SORT ignores its keys: `FROM`, `TO` and `CC` were no-ops (`cmp_fetch_items` returned `Equal`, `Address` having no `Ord`), `SUBJECT` compared the raw ENVELOPE bytes (an encoded word sorted before every letter, `Re:` and `[list]` prefixes counted, case mattered), and ties fell to the `Date:` header ascending whatever `REVERSE` said.

The local sort now reads one value per criterion and message before sorting, then compares them as RFC 5256 section 3 defines: the base subject of section 2.1 (encoded words decoded through mime-rs `codec::rfc2047::decode_text`, blanks collapsed, `re`/`fw`/`fwd` leaders, `(fwd)` trailers, leading blobs and the `[fwd: ...]` wrapper stripped), the `addr-mailbox` of the first non-group address, strings uppercased for `i;ascii-casemap`, a missing string empty. `DATE` falls back to the internal date when the header cannot be parsed, so INTERNALDATE is fetched beside the ENVELOPE. The implicit last criterion is the sequence number: the fetched map iterates by sequence number and the sort is stable, so no tie-break runs and `REVERSE` leaves ties in sequence order. A blob takes any character but a bracket, as Dovecot does, rather than the ASCII the ABNF lists. The display keys stay unsorted.

io-imap now depends on mime-rs 0.1 (`base64` and `encoding` features, no parser), which himalaya already builds.

Capabilities moved: message-sort (new spec file, requirement "The client-side sort follows RFC 5256").

Verified: four new fallback tests (subject, from with a group and a NIL list, reversed ties, date fallback) fail against the previous `cmp_fetch_items` and pass; `base_subject_strips_what_rfc5256_lists` covers the section 2.1 steps; `cargo test --all-features` passed; `cargo clippy --all-targets --all-features` clean but for the pre-existing one-element range array in src/watch.rs; `cargo build --no-default-features` builds. Live, through himalaya against Fastmail (whose Cyrus SORT is the reference) and iCloud: see the himalaya fix report of the same day.
