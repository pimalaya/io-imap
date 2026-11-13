---
cairn: delta
change: response-budgets-and-copyuid-ranges
---

## ADDED Requirements

### Requirement: An exchange collects responses within a budget

A send SHALL collect the untagged data and status responses read before its completion within a budget of responses and of summed wire octets, and fail with `ResponseTooLong` on the first response past either bound. The default budget is 16,777,216 responses and 1 GiB. CAPABILITY, ID, LOGIN and every AUTHENTICATE exchange, the commands sent before authentication, SHALL use a budget of 1024 responses and 1 MiB. The raw passthrough SHALL capture at most `max_response_len` octets, 1 GiB by default.

#### Scenario: Endless untagged run before authentication

- **WHEN** a CAPABILITY exchange reads 2000 `* 1 EXISTS` lines and no tagged completion
- **THEN** it fails with `ResponseTooLong` carrying the budget of 1024 responses and 1 MiB

#### Scenario: Budget filled exactly

- **WHEN** a send with a budget of 2 responses and 24 octets reads `* 1 EXISTS`, `* 2 EXISTS`, then its `OK`
- **THEN** it completes with both responses

### Requirement: COPYUID stays as ranges, paired in wire order

COPY and MOVE SHALL report a COPYUID as its UIDVALIDITY and its two uid-sets kept as inclusive ranges in the order of the code, never expanded, a range being ascending whichever way it is written (RFC 4315 section 4). The source and destination UIDs pair by position (RFC 4315 section 3) and SHALL be offered as a lazy iteration. A COPYUID whose two sets do not hold the same number of UIDs SHALL be dropped, the command still succeeding.

#### Scenario: Whole UID space announced

- **WHEN** a COPY completes with `OK [COPYUID 1 1:4294967295 4294967295:1]`
- **THEN** each set holds the single range `1..=4294967295`, and the count is 4294967295

#### Scenario: Copy in request order

- **WHEN** a COPY completes with `OK [COPYUID 7 5,3 10:11]`
- **THEN** the pairs are (5, 10) then (3, 11)

#### Scenario: Sets of different lengths

- **WHEN** a COPY completes with `OK [COPYUID 7 1:3 10:11]`
- **THEN** it succeeds with no COPYUID

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

### Requirement: The base subject is extracted in linear work

Extracting the base subject for the client-side sort SHALL take work linear in the length of the subject.

#### Scenario: Subject made of blobs

- **WHEN** the base subject of 1000 `[a]` blobs followed by `x` is extracted
- **THEN** it is `x`, after at most 3000 blob strips
