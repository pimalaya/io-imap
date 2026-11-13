---
cairn: delta
change: exchanges-end-on-their-own-tag
---

## MODIFIED Requirements

### Requirement: An exchange ends on its own command's completion

A send, and each FETCH body stream, ends only on the tagged completion carrying the tag of the command it belongs to: the tag it was answered with, or the tag of the command a continuation or IDLE DONE belongs to. A tagged completion with another tag is skipped, whether it decodes as it is or only once its 8-bit text is read as `?`.

#### Scenario: Foreign completion first

- **WHEN** a send for the command tagged `A1` reads `B9 NO not yours`, then `A1 OK`
- **THEN** it keeps reading after `B9`, and completes with the `A1 OK` status

#### Scenario: Foreign completion holding 8-bit text

- **WHEN** a send for the command tagged `A1` reads `B9 NO [NONEXISTENT] Mailbox doesn't exist: Été`, then `A1 OK`
- **THEN** it keeps reading after `B9`, and completes with the `A1 OK` status

#### Scenario: Foreign completion before a streamed body

- **WHEN** a FETCH body stream for the command tagged `A1` reads `B9 OK stale`
- **THEN** it asks for another read instead of completing without a body

### Requirement: A completion holding 8-bit text is read

A tagged completion of the command that fails to decode only for the 8-bit bytes of its text, which IMAP4rev1 keeps ASCII but servers send (Dovecot echoes a UTF-8 mailbox name in a `NO`), SHALL be decoded again with each such byte read as `?`, and end the exchange with its status, in a send and in the FETCH body streams alike. An untagged response that does not decode SHALL be skipped.

#### Scenario: Dovecot names a missing mailbox

- **WHEN** a send for the command tagged `A1` reads `A1 NO [NONEXISTENT] Mailbox doesn't exist: Été`
- **THEN** it completes with the `NO` status and the text `Mailbox doesn't exist: ??t??`

## ADDED Requirements

### Requirement: A LOGOUT ends on its completion, not on its BYE

An untagged BYE ends an exchange at once, the server closing the session, except for LOGOUT, whose BYE precedes its tagged completion (RFC 3501 section 6.1.3): a LOGOUT send SHALL read on to that completion, and the LOGOUT succeeds as well when the stream ends after the BYE.

#### Scenario: BYE and completion in two reads

- **WHEN** a LOGOUT tagged `A1` reads `* BYE bye`, then `A1 OK LOGOUT completed` in a second read
- **THEN** it asks for the second read and completes with success

#### Scenario: Stream closed after the BYE

- **WHEN** a LOGOUT reads `* BYE bye`, then the end of the stream
- **THEN** it completes with success

### Requirement: Bytes read past a completion stay with the connection

A FETCH body stream SHALL hand the bytes it read past its tagged completion or BYE to the connection's fragmentizer, where the next exchange reads them.

#### Scenario: BYE behind the completion

- **WHEN** a FETCH body stream reads `A1 OK done` followed by `* BYE bye` in the same read
- **THEN** it completes, and the fragmentizer holds `* BYE bye`

### Requirement: A single-message FETCH returns the requested message

`ImapMessageFetchFirst` SHALL return the items of the FETCH responses for the message it asked for, matched by sequence number, or by their `UID` item in UID mode, and fail with `MissingData` when there is none. A FETCH response for another message, which a server may send at any time (RFC 3501 section 7.4.2), is left out.

#### Scenario: Flag change of another message

- **WHEN** a UID FETCH of UID 42 reads `* 7 FETCH (UID 42)`, then `* 9 FETCH (FLAGS (\Seen))`
- **THEN** it returns the `UID 42` item alone

### Requirement: The client-side sort returns searched messages only

The SORT fallback SHALL return only the ids its SEARCH matched, whatever other FETCH responses arrive while it fetches the sort keys.

#### Scenario: FETCH of an unmatched message

- **WHEN** the search matched UIDs 1 and 2, and the key FETCH also reads `* 3 FETCH (UID 3 FLAGS (\Seen))`
- **THEN** the sorted ids hold 1 and 2 only

### Requirement: The blocking client flushes what it writes

The blocking client SHALL flush its stream after each write a coroutine asks for, before reading, so a stream that buffers still sends the command.

#### Scenario: Buffering stream

- **WHEN** a NOOP runs over a stream that holds written bytes until flushed
- **THEN** the server receives the command and the NOOP completes

### Requirement: A stream swap starts a new fragmentizer

`ImapClientStd::set_stream` SHALL replace the fragmentizer with an empty one: bytes read from the previous stream are never parsed with those of the new one.

#### Scenario: Partial line left by the previous stream

- **WHEN** the fragmentizer holds `* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN] ` without its line end and the stream is swapped
- **THEN** the next line read, `* 1 EXISTS`, is parsed alone
