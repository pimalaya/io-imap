---
cairn: tasks
change: response-codes-reach-the-caller
---

# Tasks

- [x] src/send.rs: `ImapStatusError`; `No` and `Bad` carry it in LOGIN, the six AUTHENTICATE coroutines, SELECT, EXAMINE, FETCH, STORE, COPY, MOVE and APPEND (`append::tests::tagged_no_returns_no_error` reads the kind, the code and the text)
- [x] src/client.rs: `ImapClientError::status` (`client::tests::status_gives_the_response_code_of_a_refused_command`)
- [x] src/send.rs: `ImapSendOutput::skipped` (`send::tests::skipped_untagged_response_is_kept_in_output`)
- [x] src/rfc3501/select.rs, src/rfc3501/examine.rs: `read_only`, `no_mod_seq` (`select::tests::success_collects_response`)
- [x] src/rfc3501/updates.rs: `ImapMailboxUpdates`, returned by NOOP and CHECK (`noop::tests::success_returns_mailbox_updates`)
- [x] src/rfc7677/auth_scram_sha_256.rs: the `-PLUS` name for bound credentials (`bound_credentials_announce_the_plus_mechanism`)
- [x] src/rfc3501/starttls.rs: `No`, `Bad`, `Bye` (`tagged_no_returns_no_error`, `tagged_bad_returns_bad_error`, `bye_greeting_returns_bye_error`)
- [x] CHANGELOG under [Unreleased]
- [x] Fold the delta into cairn/spec, log, land
