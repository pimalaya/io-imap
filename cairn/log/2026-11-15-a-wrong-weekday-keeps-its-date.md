---
cairn: log
change: a-wrong-weekday-keeps-its-date
landed: 2026-11-15
---

# A wrong weekday keeps its date

Found by the live testing campaign of 2026-11-15 on iCloud: a message dated `Mon, 11 Nov 2026 06:00:00 +0000` (11 November 2026 is a Wednesday) listed everywhere as 2026-11-11 and the server's `before 2026-11-12` found it, but `himalaya -a icloud envelope search -m X after 2026-11-10 order by date asc` listed it last and `imap sort -S date` put it among the day's later messages, both through the client-side sort.

The cause was the one suspected: `date_sort_key` in src/rfc5256/sort.rs parsed with chrono's `DateTime::parse_from_rfc2822`, which records the day-of-week and fails the whole header when it disagrees with the date (chrono 0.4.45, "mismatching day-of-week is always an error"). The key was `None`, so `sort_value` fell back to INTERNALDATE.

`date_sort_key` now trims the leading blanks and drops a leading day-of-week token, three ASCII letters and a comma (the shape chrono reads), before its only parse, as RFC 5322 section 3.3 makes the day-of-week informational. A correct weekday gives the same instant as before; a header that still does not parse yields `None` and falls back to the internal date, as before. No new dependency. himalaya's envelope reading (`strip_weekday`) retries on failure and needs `, ` after the token; here the token is dropped up front and the comma alone is enough, as RFC 5322 allows the date right after it.

Non-breaking: `date_sort_key` is private.

Capabilities moved: message-sort (requirement "The client-side sort follows RFC 5256" modified: the day-of-week is ignored, scenario "Wrong day-of-week" added).

Verified: `rfc5256::sort::tests::date_sort_key_ignores_a_wrong_weekday` failed on the previous code with `left: None, right: Some(2026-11-11T06:00:00+00:00)`, and `fallback_date_ignores_a_wrong_weekday` with `left: [1, 2, 3], right: [3, 1, 2]`. Both pass with the fix; the first also checks that `Mon, not a date` and `Mon,` still yield `None`, and `fallback_date_falls_back_to_the_internal_date` still passes. `cargo test --all-features` passed (358 unit, 12 integration, 47 doc tests, 10 live tests ignored); `cargo clippy --all-features` and `--all-targets` with `-D warnings` clean; `cargo build --no-default-features` builds. Tested on fakes only, no live run.
