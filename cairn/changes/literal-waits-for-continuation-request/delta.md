---
cairn: delta
change: literal-waits-for-continuation-request
---

## ADDED Requirements

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
