---
cairn: delta
change: the-raw-reply-keeps-its-bytes
---

# Delta

## ADDED Requirements

### Requirement: The raw passthrough returns the responses as received

(coroutines) `ImapRaw` SHALL return every response read until the tagged completion of every command sent, in the order received, one entry per response framed by the `Fragmentizer`, each holding its exact octets: its lines with their CRLF and its literals as sent. A line inside a literal SHALL NOT start a response. A response past the `Fragmentizer` size limit SHALL fail the exchange with `MessageTooLong`.

#### Scenario: Latin-1 literal

- **WHEN** a raw `A1 FETCH 1 BODY[]` reads `* 1 FETCH (BODY[] {4}\r\nab\xe9c)\r\n`, then `A1 OK done\r\n`
- **THEN** it returns those two responses, the octet `0xe9` kept

#### Scenario: Body line spelling a completion

- **WHEN** a raw `A1 FETCH 1 BODY[]` reads a 21-octet literal of seven `0xe9` octets, CRLF and `A1 NO forged`, then `A1 OK done`
- **THEN** it returns two responses, the literal whole in the first, and `A1 OK done` as the second

#### Scenario: Response past the read limit

- **WHEN** a raw exchange reads a response longer than the `Fragmentizer` size limit
- **THEN** it fails with `MessageTooLong`

## MODIFIED Requirements

### Requirement: A refused command reports its response code

(coroutines) The error of a command refused with NO or BAD SHALL carry the kind, the response code and the text of that completion, for every command but STARTTLS, whose reply is read without a codec. The blocking client's error SHALL give access to it without matching on the command, including for a command refused while opening a session, running a watch or sorting client-side. `ImapStatusError::code_bytes` SHALL spell the response code as on the wire, without its brackets.

#### Scenario: APPEND to a missing mailbox

- **WHEN** an APPEND completes with `NO [TRYCREATE] mailbox does not exist`
- **THEN** its error holds the kind `NO`, the code `TRYCREATE` and the text `mailbox does not exist`, and displays as `IMAP APPEND failed: NO mailbox does not exist`

#### Scenario: Authentication refused while opening a session

- **WHEN** the AUTHENTICATE PLAIN of a session being opened completes with `NO [ALERT] account disabled`
- **THEN** the client error gives the kind `NO`, the code `ALERT` and the text `account disabled`

#### Scenario: Code spelled as sent

- **WHEN** a command completes with `NO [COPYUID 7 1:3 4:6] refused`
- **THEN** `code_bytes` of its error is `COPYUID 7 1:3 4:6`

## REMOVED Requirements

None.
