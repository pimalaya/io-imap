---
cairn: log
change: authenticate-cancellation-and-command-outputs
landed: 2026-11-13
---

# AUTHENTICATE cancellation and command outputs

What response-codes-reach-the-caller left of three findings of the family audit of 2026-11-13.

- **Cancellation (IMAPA-09).** `sasl::auth_cancel::ImapAuthCancel`, crate-private and shared by the six AUTHENTICATE coroutines, sends `AuthenticateData::Cancel` under the tag of the exchange and reads the tagged reply. It is generic over the error it is built with and returns `Result<Infallible, E>`: it always completes with the mechanism error, so each coroutine holds it in one `Cancel` state and resumes it through `imap_try!`. A failed or unanswered cancellation is logged and does not replace that error: a server that fails its SCRAM proof and then drops the connection must not read as a plain end of stream. The state is entered from the two places a mechanism reads a challenge. A mechanism error before the command is written, or on the `Done` given after the tagged completion, still completes at once, the exchange being closed.
- **Status error (IMAPA-12, the rest).** `send::ImapStatusError` in the `No` and `Bad` variants of every remaining command error. STARTTLS keeps its text: it reads its reply without a codec, so it has no code to give. `ImapClientError::status` matches every command, and one level into `SessionOpen`, `MailboxWatch` and `MessageSort`. `ImapClientError::is_connection_lost` walks the error source chain for `ImapSendError::Eof`, which finds it at any depth, then matches I/O and transport errors, the three `Eof` variants of the greeting, STARTTLS and the raw passthrough, and every `Bye`, one level into the same three composites. Not seen: a BYE answering the CAPABILITY or ID chained after a login, which the next command meets as an end of stream.
- **Outputs (IMAPA-12 alerts, IMAPA-13, the rest).** `send::ImapOutput<T>` holds `data`, `alerts` and `skipped`. FETCH over a sequence set, STORE, SEARCH, SORT, THREAD, STATUS, LIST, LSUB, EXPUNGE, UID EXPUNGE, SELECT, EXAMINE, NOOP and CHECK return it; the client-side SORT adds up what its SEARCH and FETCH commands held. `send::ImapSendOutput::alerts` reads the `ALERT` codes off the untagged statuses and the completion. One wrapper for all, the result structs left as they were, so that a later change can hang the unsolicited mailbox data on the same type.

Left open, for the maintainer:

- The commands returning no data, the single-message FETCH, CAPABILITY, ID, ENABLE, LOGIN, AUTHENTICATE, the greeting and IDLE still drop the alerts and skipped lines of a successful response. Either every command returns an `ImapOutput`, or an alert becomes an event of `ImapYield`, which `imap_try!` would forward from the send through every coroutine untouched, at the price of one more arm in every caller's loop.
- The mailbox watch reads its listings as complete: a message whose FETCH line is skipped during a resync is still reported expunged. It can now tell.

Breaking: the payload of the `No` and `Bad` variants of the errors listed above; the return type of the fourteen commands above, coroutines and client methods (`select_qresync` included); NOOP and CHECK return an `ImapOutput` of the updates.

Existing tests changed: the mechanism-error tests of PLAIN, ANONYMOUS, LOGIN and SCRAM pinned the completion on the challenge itself and now expect the `*` and its reply first; the tests reading the text of a `No` or `Bad`, or the result of one of the fourteen commands, read it one field deeper.

Capabilities moved: coroutines (two requirements added, one modified), std-client (one requirement added).

Verified: the seven cancellation tests failed first with `expected WantsWrite, got Complete(Err(Mechanism(..)))`. The tests on the status of the remaining commands, on `is_connection_lost` and on the outputs read fields and a method that did not exist, so their first failure was a compile error. `cargo test --all-features` passed (322 unit, 11 integration, 47 doc tests); `cargo clippy --all-features --all-targets -- -D warnings` clean; `cargo build --no-default-features` builds.
