---
cairn: change
id: a-message-fetched-in-part-is-missing-data
status: landed
created: 2026-11-15
---

# A message fetched in part is missing data

## Why

Since a-fetch-line-keeps-what-decodes (0.11.0), a FETCH line imap-codec refuses joins `data` with the items that decode alone, the others named in `partial`. `ImapMessageFetchFirst` returns only items, never `partial`, and collects the requested message's items from `data`. A line whose requested item failed (an `ENVELOPE` that does not decode, say) therefore completes `Ok` with the other items, and the caller cannot tell it got less than it asked for. In 0.10 the whole line was skipped and the FETCH failed with `MissingData`.

## What

- `ImapMessageFetchFirst` completes with `ImapMessageFetchError::MissingData` when a `partial` entry belongs to the requested message: its `seq` equals the id asked for, or in UID mode its `uid` does. Another message's line recovered in part is ignored, as its whole lines are.
- The other coroutines reading FETCH data were checked: `ImapMessageFetch`, `ImapMessageStore`, SELECT, EXAMINE, NOOP and CHECK return `partial` beside their data, the client-side SORT adds it up, and the watcher filters it. None picks one message out of `data` and drops `partial`, so none is touched.

## Scope / non-goals

- No new error variant: `ImapMessageFetchError` is exhaustive, and a variant would break callers matching it. `MissingData` is what 0.10 returned for the same line.
- In UID mode a line whose `UID` item itself failed cannot be tied to the request; its other items lack the UID too, so they are not collected, and the FETCH fails with `MissingData` when nothing else answered.

## Decisions

- Non-breaking, for 0.11.1: no signature, field or variant changes.
