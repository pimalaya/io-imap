---
cairn: spec
capability: message-stream
---

# Message stream

## Requirements

### Requirement: A streamed body is bounded and sent once

The single FETCH body stream SHALL fail with `LiteralTooLong` when the body announces more octets than `max_literal_len` (100 MiB by default) or than the size its caller declared. The batched stream SHALL stream the body of a UID once, and fail with `UidRepeated` when a second body carries the same UID.

#### Scenario: Body announcing 4 GiB

- **WHEN** the single stream reads `* 1 FETCH (BODY[] {4294967295}`
- **THEN** it fails with `LiteralTooLong` before asking for any body octet

#### Scenario: Body repeated

- **WHEN** the batched stream reads two bodies for UID 10
- **THEN** it fails with `UidRepeated` at the second

### Requirement: A streamed APPEND announces the length it streams

The blocking client's streamed APPEND SHALL fail with `MessageTooLong`, before writing anything, when the given length does not fit the 32 bits of a literal announcement.

#### Scenario: Source over 4 GiB

- **WHEN** `append_stream` is given a length of 4294967396 octets
- **THEN** it fails with `MessageTooLong` and nothing is written to the stream
