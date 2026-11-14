---
cairn: log
change: a-fetch-line-keeps-what-decodes
landed: 2026-11-14
---

# A FETCH line keeps what decodes

An untagged FETCH line imap-codec refuses no longer loses its whole message. `ImapSend` reads the top level of a `* <number> FETCH (` message that does not decode with a scanner of its own (`FetchScanner`, src/send.rs) and decodes each item alone, as `* <number> FETCH (<item>)\r\n`, through the same `ResponseCodec`. The items that decode join `data` as one `Data::Fetch` under the line's sequence number, which the buffered FETCH merges with the other lines of the message. The others are named in `ImapOutput::partial` and `ImapSendOutput::partial`, one `ImapFetchPartial { seq, uid, failed }` per line, each failed item an `ImapFetchFailedItem { name, raw }`. Reported in pimalaya/himalaya#801 (seven nested multiparts in a `BODYSTRUCTURE`) and #641 (a keyword `Atom` refuses in `FLAGS`).

- **The scanner.** A cursor over the message bytes the fragmentizer framed, literals included. A name is a run of ASCII graphic bytes, then a section read to its closing bracket (quoted strings and literals inside taken whole), then an origin `<n>`. A value is `NIL`, a run of digits (unbounded, so a 64-bit `X-GM-MSGID` scans), a quoted string, a literal (`{n}`, `{n+}`, `~{n}`, its length checked against the bytes left) or a list, whose depth is an integer. Anything else, an atom value such as `INTERNALDATE oops` included, leaves the line in `skipped`. Every step is bounded by the message: the cursor only moves forward and never past its end.
- **Checked against imap-codec 2.0.0-alpha.10.** `body(8)` in its src/fetch.rs decodes six nested multiparts and refuses seven.
- **Names.** `name` is a `String` read lossily as UTF-8; `raw` keeps the exact bytes. The fuzz target found a section holding a byte outside UTF-8 (`THR[1\x82]`), for which the two differ.
- **The budget.** A recovered line is charged once, whether it adds data, a `partial` entry or both: `ImapSend` now counts the responses it collected instead of summing its lists.
- **A line whose items all decode alone** joins `data` with no `partial` entry. A line none of whose items decode adds no data and one `partial` entry.
- **The watcher.** Beyond the delta as proposed, a message whose `UID`, `FLAGS` or `MODSEQ` failed is left out of the baseline, the whole-mailbox re-read and the QRESYNC reply. Without it, a line whose `FLAGS` failed would reach the shadow with no flags and report every known flag of the message as removed. The proposal only named the snapshot's completeness; the mailbox-watch spec states both.
- **The client-side SORT** adds up the `partial` of its FETCH commands. A message missing its sort key is now sorted with the key absent instead of being dropped from the result.
- **Upstream.** The imap-codec issue is drafted in cairn/changes/a-fetch-line-keeps-what-decodes/imap-codec-issue.md, for the maintainer to post.

Breaking: `ImapOutput` and `ImapSendOutput` gain the public field `partial`.

Existing tests changed, for the line now recovered in part: `fetch::tests::fetch_returns_skipped_lines_and_alerts` (renamed `fetch_returns_partial_lines_and_alerts`, the delta's scenario), `noop::tests::success_returns_mailbox_updates`. `watch::tests::a_listing_that_skipped_a_line_removes_nothing` and `a_qresync_reply_that_skipped_a_line_keeps_the_resync_point` now feed a line that does not scan, to keep testing a skipped line.

Capabilities moved: message-fetch (one requirement added), coroutines (two requirements modified), mailbox-watch (one requirement modified).

Verified: the two new watcher tests, `a_listing_missing_flags_keeps_the_known_ones` and `a_qresync_reply_missing_flags_keeps_the_resync_point`, fail with the filter of `unreadable` removed. The scanner unit tests cover truncations and single-byte alterations of a line holding a section, a literal, a literal8 and escaped quotes, and a list nested a million deep. The `fetch_line` fuzz target ran 5,398,482 inputs in 301 seconds with no failure (coverage 4144, corpus 3628), after a first run of 112 inputs stopped on the lossy name, an oracle fix. `cargo test --all-features` passed (345 unit, 12 integration, 47 doc tests); `cargo clippy --all-targets -- -D warnings` clean with `--all-features` and `--no-default-features --features rustls-ring`, and `--lib` clean with no default features, `scram`, `client`, `rustls-aws` and `native-tls`; `cargo doc` clean under `-D rustdoc::broken_intra_doc_links -D warnings`.
