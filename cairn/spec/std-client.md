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

`ImapClientStd::set_stream` SHALL replace the fragmentizer with an empty one: bytes read from the previous stream are never parsed with those of the new one.

#### Scenario: Partial line left by the previous stream

- **WHEN** the fragmentizer holds `* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN] ` without its line end and the stream is swapped
- **THEN** the next line read, `* 1 EXISTS`, is parsed alone
