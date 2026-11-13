---
cairn: log
change: response-codes-reach-the-caller
landed: 2026-11-13
---

# Response codes and skipped data reach the caller

Findings of the family audit of 2026-11-13. Six landed, two of them in part, and one did not.

- **Status error (IMAPA-12, in part).** `send::ImapStatusError` holds the kind, the response code and the text of a NO or BAD completion, built from the `StatusBody` and displayed as its text. It lives in src/send.rs so that the `send::*` import every coroutine already has brings it. The `No` and `Bad` variants keep their names and messages and change payload, from `String` to this type, in LOGIN, the six AUTHENTICATE coroutines, SELECT, EXAMINE, FETCH, STORE, COPY, MOVE and the buffered APPEND: the break is one field access for a caller that read the text. The XOAUTH2 and OAUTHBEARER `NoWithError` variants keep their `info: String`. `ImapClientError::status` returns the status for those commands and `None` otherwise. Left: every other command error, `Bye`, an `is_connection_lost` classifier, and `ALERT` codes on the outputs.
- **Skipped responses (IMAPA-13, in part).** `ImapSendOutput::skipped` keeps the raw bytes of each skipped untagged response, as a `Secret` like the error payloads, charged to the budget. The coroutines wrapping a send still drop it with the rest of the output.
- **SELECT codes (IMAPB-17).** `ImapMailboxSelectData::read_only` and `no_mod_seq`, read by one `read_access_code` off the completion and the untagged OK lines, in SELECT and EXAMINE.
- **Mailbox updates (IMAPB-08, as scoped).** `rfc3501::updates::ImapMailboxUpdates`, returned by NOOP and CHECK. The other commands still drop unsolicited data, and the default form (sequence numbers) of the commands taking a `uid` option is unchanged: an API decision.
- **SCRAM name (IMAPA-08).** The mechanism name follows `SaslCoroutine::mechanism`.
- **STARTTLS status (IMAPA-10).** A byte compare of the word after the tag, and of the greeting against `* BYE`; no codec in cleartext.
- **Cancellation (IMAPA-09): not done.** A mechanism error after a continuation request still completes at once. The fix is a cancel state in each of the six AUTHENTICATE coroutines: send `AuthenticateData::Cancel` under the tag of the exchange, read the tagged reply, then complete with the mechanism error.

Breaking: the payload of the `No` and `Bad` variants listed above; the return type of NOOP and CHECK (coroutines and client methods); new fields on `ImapSendOutput` and `ImapMailboxSelectData`; new variants on `ImapStartTlsError`.

Capabilities moved: coroutines (five requirements added), mailbox-select (opening codes added).

Verified: `starttls::tests::tagged_no_returns_no_error`, `tagged_bad_returns_bad_error` and `bye_greeting_returns_bye_error` failed first (the coroutine completed `Ok`, or asked for a tag after the BYE), as did `bound_credentials_announce_the_plus_mechanism` (it wrote `AUTHENTICATE SCRAM-SHA-256`). The other tests read fields and types that did not exist. `cargo test --all-features` passed (312 unit, 11 integration, 47 doc tests); `cargo clippy --all-features --all-targets -- -D warnings` clean; `cargo build --no-default-features` builds.
