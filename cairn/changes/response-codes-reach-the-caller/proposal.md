---
cairn: change
id: response-codes-reach-the-caller
status: landed
created: 2026-11-13
---

# Response codes and skipped data reach the caller

## Why

Findings of the family audit of 2026-11-13 on what the coroutines read and then drop, each re-checked against the code the same day.

- **Status errors keep the text alone (IMAPA-12).** Every command error held `No(String)` and `Bad(String)`: the response code of the completion was dropped, so a caller could not tell `NO [AUTHENTICATIONFAILED]` from `NO [UNAVAILABLE]`, or `NO [TRYCREATE]` from any other refusal, without parsing free text.
- **A skipped response leaves no trace (IMAPA-13).** An untagged response that does not decode is skipped on purpose; only a debug line said so, and a listing missing one message looked complete.
- **SELECT and EXAMINE drop the completion code (IMAPB-17).** `READ-ONLY`, `READ-WRITE` and `NOMODSEQ` were never read.
- **Unsolicited mailbox data is dropped (IMAPB-08).** NOOP, documented as a way to poll for updates, returned `()`, as did CHECK: the EXISTS and EXPUNGE a server sends with them were read and discarded.
- **Bound SCRAM under the unbound name (IMAPA-08).** `ImapAuthScramSha256` announced `SCRAM-SHA-256` whatever the credentials, so bound ones sent a `p=` header under a mechanism name a server must refuse it with.
- **STARTTLS reads no status (IMAPA-10).** `ImapStartTls` completed `Ok` on any tagged line, `NO` and `BAD` included, and discarded its greeting unread, a `BYE` included. It failed closed, on the TLS handshake rather than on the server's words.

## What

- `send::ImapStatusError` (`kind`, `code`, `text`, displayed as the text) replaces the `String` of the `No` and `Bad` variants of the LOGIN, AUTHENTICATE (six mechanisms), SELECT, EXAMINE, FETCH, STORE, COPY, MOVE and buffered APPEND errors. The variant names and the error messages are unchanged. `ImapClientError::status` returns it for those commands.
- `ImapSendOutput::skipped` keeps the raw bytes of every skipped untagged response; they count against the budget.
- `ImapMailboxSelectData` gains `read_only` and `no_mod_seq`.
- `rfc3501::updates::ImapMailboxUpdates` (EXISTS, RECENT, EXPUNGE, VANISHED, FETCH) is what NOOP and CHECK return.
- The SCRAM coroutine takes its mechanism name from the mechanism.
- `ImapStartTls` fails with `No`, `Bad` or `Bye`.

## Not done

- IMAPA-09: a mechanism failing after a continuation request still completes without sending the `*` cancellation. It needs a cancel state in each of the six AUTHENTICATE coroutines.
- IMAPA-12, the rest: the other command errors still hold `No(String)` and `Bad(String)` (the two FETCH streams, the streamed APPEND, APPENDUID, SEARCH, SORT, THREAD, STATUS, LIST, LSUB, the mailbox management commands, ID, ENABLE, CAPABILITY, NOOP, CHECK, CLOSE, UNSELECT, EXPUNGE, LOGOUT, IDLE); `Bye` keeps its text; `ImapClientError` has no `is_connection_lost`; `ALERT` codes are in `ImapSendOutput::untagged` but no command output surfaces them.
- IMAPA-13, the rest: the coroutines wrapping a send do not return its `skipped` lines.
- IMAPB-08, the rest: the other commands still drop unsolicited mailbox data, and sequence numbers stay the default of the commands taking a `uid` option, which is an API decision.
