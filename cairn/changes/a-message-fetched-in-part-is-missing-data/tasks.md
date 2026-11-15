---
cairn: tasks
change: a-message-fetched-in-part-is-missing-data
---

# Tasks

- [x] src/rfc3501/fetch.rs: `ImapMessageFetchFirst` fails with `MissingData` when the requested message is in `partial` (`fetch::tests::first_with_an_item_that_does_not_decode_returns_missing_data_error`, failing on 0.11.0), and ignores another message's (`first_ignores_another_message_recovered_in_part`)
- [x] Check the other coroutines reading FETCH data: none picks one message out of `data`
- [x] CHANGELOG under [Unreleased]
- [x] Fold the delta into cairn/spec, log, land
