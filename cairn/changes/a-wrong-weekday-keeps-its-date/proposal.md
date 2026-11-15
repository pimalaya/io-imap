---
cairn: change
id: a-wrong-weekday-keeps-its-date
status: landed
created: 2026-11-15
---

# A wrong weekday keeps its date

## Why

The client-side sort reads the `DATE` key through chrono's `DateTime::parse_from_rfc2822`, which fails the whole header when its day-of-week disagrees with its date (chrono 0.4.45 documents "mismatching day-of-week is always an error"). The key then falls back to the internal date, so such a message sorts at its arrival time while every listing shows it at its sent date.

RFC 5256 section 2.2 sorts by the sent date, and RFC 5322 section 3.3 makes the day-of-week informational: a wrong one does not change the date.

The live testing campaign of 2026-11-15 met such a message: `Date: Mon, 11 Nov 2026 06:00:00 +0000` (11 November 2026 is a Wednesday) lists everywhere as 2026-11-11 and the server's `before 2026-11-12` finds it, but a fallback sort by `DATE` placed it among the later messages of its arrival.

## What

- `date_sort_key` drops a leading day-of-week token (three letters and a comma, the shape chrono reads) before parsing, so a date with a wrong or unknown day name sorts by its date and time.
- A header that still does not parse falls back to the internal date, as before.
- No new dependency: chrono parses the remainder, which its RFC 2822 grammar allows without a day-of-week.

## Scope / non-goals

- Only the day-of-week is relaxed. Other malformed dates (a missing zone, a long month name) still fall back to the internal date.
- The server SORT path is untouched.

## Decisions

- **Strip, then parse once.** The token is dropped before the only parse rather than on a retry: a correct weekday gives the same instant either way, and the common path keeps one parse.
- Non-breaking, for a patch release: `date_sort_key` is private.
