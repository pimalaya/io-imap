---
cairn: spec
capability: std-client
---

# Blocking client

## Requirements

### Requirement: The blocking client flushes what it writes

The blocking client SHALL flush its stream after each write a coroutine asks for, before reading, so a stream that buffers still sends the command.

#### Scenario: Buffering stream

- **WHEN** a NOOP runs over a stream that holds written bytes until flushed
- **THEN** the server receives the command and the NOOP completes

### Requirement: A stream swap starts a new fragmentizer

`ImapClientStd::set_stream` SHALL empty the fragmentizer, keeping the message size it was configured with: bytes read from the previous stream are never parsed with those of the new one.

#### Scenario: Partial line left by the previous stream

- **WHEN** the fragmentizer holds `* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN] ` without its line end and the stream is swapped
- **THEN** the next line read, `* 1 EXISTS`, is parsed alone

#### Scenario: Custom message size

- **WHEN** the client's fragmentizer was built for messages of 8 octets and the stream is swapped
- **THEN** the next message is still cut at 8 octets

### Requirement: Closing a watch stream never waits on its own events

`ImapMailboxWatchStream` SHALL drop its event receiver before joining its worker, on `close`, `into_state` and drop alike, so a worker blocked on a full channel returns. `into_state` SHALL return the state the watch ended with.

#### Scenario: Events nobody drains

- **WHEN** the worker holds more events than the channel takes and the stream is closed without being drained
- **THEN** `close` returns

### Requirement: The client error tells a lost connection

`ImapClientError::is_connection_lost` SHALL be true when reading or writing the stream failed, when the stream ended during an exchange, whatever the depth at which the error holds it, and when the command, or a command sent while opening a session, running a watch or sorting client-side, was answered with a BYE. It SHALL be false for a refused command. A BYE answering the CAPABILITY or ID chained after a login is not reported: the next command fails on the end of the stream.

#### Scenario: Stream ended while opening a session

- **WHEN** the AUTHENTICATE of a session being opened reads the end of the stream
- **THEN** the client error says the connection is lost

#### Scenario: Refused COPY

- **WHEN** a COPY completes with `NO mailbox does not exist`
- **THEN** the client error says the connection is not lost
