---
cairn: delta
change: response-codes-reach-the-caller
---

## ADDED Requirements

### Requirement: A refused command reports its response code

The error of a command refused with NO or BAD SHALL carry the kind, the response code and the text of that completion, for LOGIN, AUTHENTICATE, SELECT, EXAMINE, FETCH, STORE, COPY, MOVE and the buffered APPEND. The blocking client's error SHALL give access to it without matching on the command.

#### Scenario: APPEND to a missing mailbox

- **WHEN** an APPEND completes with `NO [TRYCREATE] mailbox does not exist`
- **THEN** its error holds the kind `NO`, the code `TRYCREATE` and the text `mailbox does not exist`, and displays as `IMAP APPEND failed: NO mailbox does not exist`

### Requirement: A skipped response is kept

A send SHALL keep the raw bytes of every untagged response it skipped for not decoding, in its output, counted against its budget.

#### Scenario: Undecodable FLAGS line

- **WHEN** a send reads `* FLAGS (OIB-Seen-[Gmail]/All Mail)`, then its `OK`
- **THEN** it completes, and its output holds that line as skipped

### Requirement: SELECT and EXAMINE report how the mailbox was opened

The data of a SELECT or EXAMINE SHALL say whether the mailbox was opened read-only (`READ-ONLY` or `READ-WRITE` code of the completion, unknown when neither) and whether it keeps no modification sequences (`NOMODSEQ` code).

#### Scenario: Read-write mailbox without modification sequences

- **WHEN** a SELECT reads `* OK [NOMODSEQ] ...`, then `OK [READ-WRITE] SELECT completed`
- **THEN** its data says not read-only, and no modification sequences

### Requirement: NOOP and CHECK return the mailbox updates

NOOP and CHECK SHALL return what the server reports of the selected mailbox with their response: the EXISTS and RECENT counts, the expunged sequence numbers in the order sent, the vanished UID ranges and the FETCH data.

#### Scenario: Two expunges and a new message

- **WHEN** a NOOP reads `* 3 EXPUNGE`, `* 3 EXPUNGE`, `* 5 EXISTS`, then its `OK`
- **THEN** it returns the expunged sequence numbers 3 and 3, and 5 messages

### Requirement: A bound SCRAM exchange runs under the PLUS name

The SCRAM-SHA-256 coroutine SHALL announce `SCRAM-SHA-256-PLUS` when its credentials carry a channel binding, and `SCRAM-SHA-256` otherwise.

#### Scenario: Bound credentials

- **WHEN** the credentials carry a `tls-exporter` binding
- **THEN** the command written is `AUTHENTICATE SCRAM-SHA-256-PLUS`

### Requirement: STARTTLS completes on OK only

The STARTTLS coroutine SHALL complete with success only on a tagged `OK`, fail with `No` or `Bad` carrying the server's text on any other tagged reply, and fail with `Bye` when the greeting is a BYE.

#### Scenario: TLS refused

- **WHEN** the server answers `A1 NO TLS not available`
- **THEN** the coroutine fails with `No` and the text `TLS not available`

#### Scenario: BYE greeting

- **WHEN** the server greets with `* BYE overloaded`
- **THEN** the coroutine fails with `Bye` and the text `overloaded` without writing STARTTLS
