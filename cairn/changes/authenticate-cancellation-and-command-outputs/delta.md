---
cairn: delta
change: authenticate-cancellation-and-command-outputs
---

## ADDED Requirements

### Requirement: A refused mechanism cancels its AUTHENTICATE exchange

An AUTHENTICATE coroutine whose mechanism refuses a challenge SHALL send the `*` cancellation under the tag of the exchange (RFC 3501 section 6.2.2), read the tagged reply, then fail with the error of the mechanism, whatever the reply and when the stream ends before it. A mechanism error raised before the command is written, or once the tagged completion is read, fails at once.

#### Scenario: Challenge after the credentials went inline

- **WHEN** an AUTHENTICATE PLAIN tagged `A1` sent its credentials inline and reads `+ `
- **THEN** it writes `*`, reads `A1 BAD AUTHENTICATE cancelled`, and fails with the mechanism's `UnexpectedChallenge`

#### Scenario: Cancellation left unanswered

- **WHEN** the stream ends after the `*` is written
- **THEN** the coroutine fails with the error of the mechanism, not with the end of stream

### Requirement: A command returning data returns what its response held beside it

FETCH over a sequence set, STORE, SEARCH, SORT, THREAD, STATUS, LIST, LSUB, EXPUNGE, UID EXPUNGE, SELECT, EXAMINE, NOOP and CHECK SHALL complete with an output holding their result, the texts of the `ALERT` response codes read in the untagged status responses and in the completion, and the untagged responses skipped for not decoding. The client-side SORT SHALL add up those of its SEARCH and of each of its FETCH commands.

#### Scenario: One FETCH line does not decode

- **WHEN** a FETCH reads `* 1 FETCH (FLAGS (\Seen))`, `* 2 FETCH (FLAGS (OIB-Seen-[Gmail]/All Mail))`, `* OK [ALERT] quota almost reached`, then its `OK`
- **THEN** its output holds the data of message 1, the second line as skipped, and the alert `quota almost reached`

#### Scenario: Client-side SORT

- **WHEN** the SEARCH of a client-side SORT skips one line and its FETCH another
- **THEN** the output of the SORT holds both lines as skipped

### Requirement: The client error tells a lost connection

`ImapClientError::is_connection_lost` SHALL be true when reading or writing the stream failed, when the stream ended during an exchange, whatever the depth at which the error holds it, and when the command, or a command sent while opening a session, running a watch or sorting client-side, was answered with a BYE. It SHALL be false for a refused command. A BYE answering the CAPABILITY or ID chained after a login is not reported: the next command fails on the end of the stream.

#### Scenario: Stream ended while opening a session

- **WHEN** the AUTHENTICATE of a session being opened reads the end of the stream
- **THEN** the client error says the connection is lost

#### Scenario: Refused COPY

- **WHEN** a COPY completes with `NO mailbox does not exist`
- **THEN** the client error says the connection is not lost

## MODIFIED Requirements

### Requirement: A refused command reports its response code

The error of a command refused with NO or BAD SHALL carry the kind, the response code and the text of that completion, for every command but STARTTLS, whose reply is read without a codec. The blocking client's error SHALL give access to it without matching on the command, including for a command refused while opening a session, running a watch or sorting client-side.

#### Scenario: APPEND to a missing mailbox

- **WHEN** an APPEND completes with `NO [TRYCREATE] mailbox does not exist`
- **THEN** its error holds the kind `NO`, the code `TRYCREATE` and the text `mailbox does not exist`, and displays as `IMAP APPEND failed: NO mailbox does not exist`

#### Scenario: Authentication refused while opening a session

- **WHEN** the AUTHENTICATE PLAIN of a session being opened completes with `NO [ALERT] account disabled`
- **THEN** the client error gives the kind `NO`, the code `ALERT` and the text `account disabled`
