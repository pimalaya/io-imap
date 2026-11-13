---
cairn: change
id: authenticate-cancellation-and-command-outputs
status: landed
created: 2026-11-13
---

# AUTHENTICATE cancellation and command outputs

## Why

What the change response-codes-reach-the-caller left of three findings of the family audit of 2026-11-13, each re-checked against the code the same day.

- **A refused mechanism leaves its exchange open (IMAPA-09).** When a mechanism refused a challenge, the AUTHENTICATE coroutine completed at once, the server still waiting for a response line. The next command on the connection was read as that line: the server answered the old tag, never ran the new command, and the client waited on a completion that could not come.
- **Status errors keep the text alone (IMAPA-12, the rest).** Thirty command errors still held `No(String)` and `Bad(String)`. `ImapClientError::status` answered for the top-level commands only, so the refusal of a LOGIN or AUTHENTICATE sent while opening a session gave no response code. Nothing told a lost connection from a refused command short of matching every variant. No command output carried the `ALERT` codes a client must show its user.
- **A skipped response leaves no trace in the results (IMAPA-13, the rest).** A send kept the lines it skipped, the coroutines wrapping it dropped them: a listing missing a row still looked complete.

## What

- `sasl::auth_cancel::ImapAuthCancel`, crate-private, sends `AuthenticateData::Cancel` under the tag of the exchange, reads the tagged reply and completes with the mechanism error it was given. The six AUTHENTICATE coroutines gain a `Cancel` state holding it, entered when the mechanism fails on a challenge.
- `send::ImapStatusError` in the `No` and `Bad` variants of every remaining command error: both FETCH streams, streamed APPEND, APPENDUID, SEARCH, SORT, THREAD, STATUS, LIST, LSUB, CREATE, DELETE, RENAME, SUBSCRIBE, UNSUBSCRIBE, ID, ENABLE, CAPABILITY, NOOP, CHECK, CLOSE, UNSELECT, EXPUNGE, UID EXPUNGE, LOGOUT and IDLE.
- `ImapClientError::status` covers every command, and the commands sent while opening a session, running a watch or a client-side SORT. `ImapClientError::is_connection_lost` is true on an I/O or transport error, an end of stream found anywhere in the error chain, and a BYE.
- `send::ImapOutput<T>` (`data`, `alerts`, `skipped`) is what FETCH, STORE, SEARCH, SORT, THREAD, STATUS, LIST, LSUB, EXPUNGE, UID EXPUNGE, SELECT, EXAMINE, NOOP and CHECK return. `send::ImapSendOutput::alerts` reads the alerts off an exchange.

## Not done

- STARTTLS keeps `No(String)` and `Bad(String)`: it reads its reply without a codec, on purpose, so it has no response code to give.
- `Bye` variants keep their text.
- The commands returning no data (CREATE, DELETE, RENAME, SUBSCRIBE, UNSUBSCRIBE, CLOSE, UNSELECT, LOGOUT, the silent STORE, COPY, MOVE, APPEND), the single-message FETCH, CAPABILITY, ID, ENABLE, LOGIN, the AUTHENTICATE coroutines, the greeting and IDLE still drop the alerts and the skipped lines of a successful response. An alert on their NO or BAD is in the status error. Carrying them means either an `ImapOutput` on every command or an alert event in `ImapYield`: the maintainer's choice.
- The mailbox watch reads its listings as complete: a message whose FETCH line is skipped during a resync is still reported expunged. It can now tell (`ImapOutput::skipped`); what it does then (fail, or hold back the expunges) is not decided.
