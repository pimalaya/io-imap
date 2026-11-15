---
cairn: log
change: a-message-fetched-in-part-is-missing-data
landed: 2026-11-15
---

# A message fetched in part is missing data

`ImapMessageFetchFirst` fails with `MissingData` again when the line of the requested message was recovered in part, a regression of 0.11.0's `partial`: it collected the decoded items from `data` and completed `Ok` without the item that failed. A `partial` entry is the requested message's when its `seq` equals the id asked for, or in UID mode when its `uid` does. The collected items are dropped in that case, so the completion keeps its order: `NO` and `BAD` still win, and an `OK` gives `MissingData`.

The other coroutines reading FETCH data were checked and left alone: `ImapMessageFetch`, STORE, SELECT, EXAMINE, NOOP and CHECK hand `partial` to the caller beside their data, the client-side SORT adds it up, and the watcher filters it. None of them picks one message out of `data` while dropping `partial`.

Non-breaking: no signature, field or variant changes; only the doc of `ImapMessageFetchError::MissingData` names the new cause.

Capabilities moved: message-fetch (one requirement modified).

Verified: `fetch::tests::first_with_an_item_that_does_not_decode_returns_missing_data_error` (`* 42 FETCH (UID 100 FLAGS (\Seen) ENVELOPE (NIL))` by sequence number, `* 7 FETCH (UID 42 …)` by UID) failed before the fix with `Complete(Ok([Uid(100), Flags([Flag(Seen)])]))` and passes after; `first_ignores_another_message_recovered_in_part` keeps an unsolicited partial line from failing the request.
