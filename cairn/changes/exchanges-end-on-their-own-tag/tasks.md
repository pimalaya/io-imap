---
cairn: tasks
change: exchanges-end-on-their-own-tag
---

# Tasks

- [x] src/send.rs: `decode_completion` and `decode_lossy_tagged`, crate-private; a foreign completion holding 8-bit text is skipped (`send::tests::a_foreign_completion_holding_8bit_text_is_skipped`)
- [x] src/send.rs: a LOGOUT send reads past its BYE to the tagged completion, and completes on EOF after the BYE; src/rfc3501/logout.rs accepts the BYE alone (`logout::tests::bye_and_completion_in_two_reads_return_ok`, `bye_then_eof_returns_ok`)
- [x] src/rfc3501/fetch_stream.rs and src/rfc3501/fetch_stream_batch.rs: the tag is kept and compared, a completion holding 8-bit text is read (`foreign_completion_is_skipped`, `completion_holding_8bit_text_is_read` in both test modules)
- [x] Both streams hand the bytes read past their completion to the fragmentizer (`bytes_past_completion_return_to_fragmentizer` in both test modules)
- [x] src/rfc3501/fetch.rs: `ImapMessageFetchFirst` takes the FETCH of the requested message only (`fetch::tests::first_skips_fetch_of_another_message`, `first_with_only_another_message_returns_missing_data_error`)
- [x] src/rfc5256/sort.rs: the fallback returns searched ids only (`sort::tests::fallback_leaves_out_messages_the_search_did_not_match`)
- [x] src/client.rs and src/client/connect.rs: flush after each write (`client::tests::commands_are_flushed_before_reading`)
- [x] src/client.rs: `set_stream` starts a new fragmentizer (`client::tests::set_stream_forgets_bytes_of_the_previous_stream`)
- [x] src/watch.rs: the one-element range array clippy refused in a test
- [x] CHANGELOG under [Unreleased]
- [x] Fold the delta into cairn/spec, log, land
