---
cairn: spec
capability: coroutines
---

# Coroutines

## Requirements

### Requirement: Command tags come from the caller

A coroutine never generates a command tag. Before writing each tagged command, it yields `WantsTag` and builds the command from the tag the caller resumes it with. A composite starts each sub-coroutine with no input, so bytes answering one command are never read as the next command's tag.

#### Scenario: Tag answered

- **WHEN** a coroutine yields `WantsTag` and is resumed with `A1`
- **THEN** it yields `WantsWrite` with a command tagged `A1`

#### Scenario: Tag missing or invalid

- **WHEN** a coroutine yields `WantsTag` and is resumed with nothing, or with bytes that are not a valid tag
- **THEN** it completes with `MissingTag` or `InvalidTag`

#### Scenario: Chained command

- **WHEN** a composite's command completes on the bytes the caller resumed it with, and the composite chains another command
- **THEN** it yields `WantsTag` for that command instead of reading those bytes as its tag

### Requirement: The bare core is no_std

Building io-imap without default features enables no `std` feature in its dependency tree. Only the `client` feature pulls std, including the imap-types tag generator `ImapClientStd` answers `WantsTag` with.

#### Scenario: Bare build

- **WHEN** io-imap is built with `--no-default-features`
- **THEN** no dependency has its `std` feature enabled

### Requirement: An exchange ends on its own command's completion

A send ends only on the tagged completion carrying the tag of the command it belongs to: the tag it was answered with, or the tag of the command a continuation or IDLE DONE belongs to. A tagged completion with another tag is skipped.

#### Scenario: Foreign completion first

- **WHEN** a send for the command tagged `A1` reads `B9 NO not yours`, then `A1 OK`
- **THEN** it keeps reading after `B9`, and completes with the `A1 OK` status

### Requirement: A completion holding 8-bit text is read

A tagged completion of the command that fails to decode only for the 8-bit bytes of its text, which IMAP4rev1 keeps ASCII but servers send (Dovecot echoes a UTF-8 mailbox name in a `NO`), SHALL be decoded again with each such byte read as `?`, and end the exchange with its status. An untagged response that does not decode SHALL be skipped.

#### Scenario: Dovecot names a missing mailbox

- **WHEN** a send for the command tagged `A1` reads `A1 NO [NONEXISTENT] Mailbox doesn't exist: Été`
- **THEN** it completes with the `NO` status and the text `Mailbox doesn't exist: ??t??`

### Requirement: A synchronising literal waits for its continuation request

A send SHALL write a synchronising literal only after decoding a command continuation request read since the line announcing that literal was written (RFC 3501 sections 4.3 and 7.5). Bytes holding no continuation request (an untagged response, a completion of another command, part of a line) SHALL leave the literal unsent and the send reading. One continuation request releases one literal. A tagged completion of the command, or a BYE, read in place of the continuation request ends the exchange with the literal unsent.

#### Scenario: Untagged line first

- **WHEN** a send wrote `A1 APPEND INBOX {2}` and reads `* OK [ALERT] mailbox almost full`
- **THEN** it asks for another read, and writes the literal once it reads `+ go`

#### Scenario: Continuation request split across reads

- **WHEN** a send wrote `A1 APPEND INBOX {2}` and reads `+ g`, then `o` and the line end
- **THEN** it writes the literal after the second read only, and completes with the `A1 OK` status read next

#### Scenario: Refusal split across reads

- **WHEN** a send wrote `A1 APPEND INBOX {2}` and reads `A1 NO [OVERQUOTA] quota exc`, then `eeded` and the line end
- **THEN** it completes with the `NO` status and never writes the literal

### Requirement: An exchange collects responses within a budget

A send SHALL collect the untagged data and status responses read before its completion within a budget of responses and of summed wire octets, and fail with `ResponseTooLong` on the first response past either bound. The default budget is 16,777,216 responses and 1 GiB. CAPABILITY, ID, LOGIN and every AUTHENTICATE exchange, the commands sent before authentication, SHALL use a budget of 1024 responses and 1 MiB. The raw passthrough SHALL capture at most `max_response_len` octets, 1 GiB by default.

#### Scenario: Endless untagged run before authentication

- **WHEN** a CAPABILITY exchange reads 2000 `* 1 EXISTS` lines and no tagged completion
- **THEN** it fails with `ResponseTooLong` carrying the budget of 1024 responses and 1 MiB

#### Scenario: Budget filled exactly

- **WHEN** a send with a budget of 2 responses and 24 octets reads `* 1 EXISTS`, `* 2 EXISTS`, then its `OK`
- **THEN** it completes with both responses
