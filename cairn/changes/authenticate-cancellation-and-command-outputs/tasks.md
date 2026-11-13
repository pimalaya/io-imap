---
cairn: tasks
change: authenticate-cancellation-and-command-outputs
---

# Tasks

- [x] src/sasl/auth_cancel.rs: `ImapAuthCancel`, completing with the mechanism error even when its `*` gets no reply (`auth_cancel::tests::unanswered_cancellation_returns_the_given_error`)
- [x] The six AUTHENTICATE coroutines: `Cancel` state (`ir_extra_challenge_returns_mechanism_error` in auth_plain, auth_anonymous, auth_xoauth2 and auth_oauthbearer, `ir_extra_prompt_returns_mechanism_error` in auth_login, `ir_server_error_returns_mechanism_error` and `non_ir_server_error_returns_mechanism_error` in auth_scram_sha_256)
- [x] `ImapStatusError` in every remaining `No` and `Bad` variant (`append_stream::tests::continuation_no_returns_no_error` and `fetch_stream::tests::tagged_no_returns_no_error` read the kind, the code and the text)
- [x] src/client.rs: `status` for every command and for a failed session (`client::tests::status_gives_the_response_code_of_a_refused_session`)
- [x] src/client.rs: `is_connection_lost` (`client::tests::connection_is_lost_on_eof_bye_and_io_error`, `connection_is_kept_on_a_refused_command`)
- [x] src/send.rs: `ImapOutput`, `ImapSendOutput::alerts` (`send::tests::alerts_are_read_off_untagged_and_tagged_statuses`)
- [x] FETCH, STORE, SEARCH, SORT, THREAD, STATUS, LIST, LSUB, EXPUNGE, UID EXPUNGE, SELECT, EXAMINE, NOOP, CHECK return an `ImapOutput` (`fetch::tests::fetch_returns_skipped_lines_and_alerts`, `list::tests::skipped_row_is_returned_beside_the_rows`, `noop::tests::success_returns_mailbox_updates`, `sort::tests::fallback_returns_lines_skipped_by_search_and_fetch`, `select_skips_undecodable_untagged_lines` in tests/rfc3501.rs)
- [x] src/watch.rs, tests/common.rs, examples: read the `data` of the outputs
- [x] CHANGELOG under [Unreleased]
- [x] Fold the delta into cairn/spec, log, land
