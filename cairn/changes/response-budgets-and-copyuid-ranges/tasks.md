---
cairn: tasks
change: response-budgets-and-copyuid-ranges
---

# Tasks

- [x] src/send.rs: `ImapSendBudget`, `ImapSend::budget`, `ImapSendError::ResponseTooLong`, charged on each collected data and untagged status response
- [x] `ImapSendBudget::PRE_AUTH` set by src/rfc3501/capability.rs, src/rfc3501/login.rs, src/rfc2971/id.rs and the six AUTHENTICATE coroutines (src/sasl, src/rfc7628, src/rfc7677), on the command and on each continuation
- [x] Tests: `capability::tests::endless_untagged_run_returns_too_long_error` (yielded `WantsRead` forever before), `send::tests::responses_over_budget_return_too_long_error`, `send::tests::responses_filling_budget_are_collected`
- [x] src/rfc3501/raw.rs: `ImapRaw::max_response_len`, `DEFAULT_MAX_RESPONSE_LEN`, `ImapRawError::ResponseTooLong` (`raw::tests::response_over_max_len_returns_too_long_error`)
- [x] src/rfc3501/copy.rs: `ImapCopyUid` as ranges in wire order with `pairs` and `count`, sets of different lengths dropped; src/rfc6851/move.rs and src/client.rs return `Option<ImapCopyUid>`
- [x] Tests: `copy::tests::copyuid_ranges_stay_unexpanded`, `copyuid_pairs_follow_wire_order`, `copyuid_sets_of_different_lengths_give_none` (each failed against the expansion, written for the previous shape); the COPY and MOVE tests pinning the sorted vectors now assert the pairs
- [x] src/rfc3501/fetch_stream.rs: `ImapMessageFetchStreamOptions`, `LiteralTooLong` (`fetch_stream::tests::literal_over_max_fails`, `literal_over_declared_size_fails`)
- [x] src/rfc3501/fetch_stream_batch.rs: a UID's body is streamed once, `UidRepeated` (`fetch_stream_batch::tests::repeated_uid_fails`)
- [x] src/client.rs: `append_stream` fails with `ImapClientError::MessageTooLong` before writing (`client::tests::append_stream_over_u32_fails_before_writing`)
- [x] src/rfc5256/sort.rs: blobs stripped in one pass (`sort::tests::base_subject_work_is_linear_in_blobs`, counting `strip_blob` calls)
- [x] fuzz/fuzz_targets/response.rs: COPY and MOVE, the COPYUID oracle, the body stream answering its tag; fuzz/README.md
- [x] examples/tokio_fetch_stream.rs and tests/common.rs follow the new constructors
- [x] CHANGELOG under [Unreleased]
- [x] Fold the delta into cairn/spec, log, land
