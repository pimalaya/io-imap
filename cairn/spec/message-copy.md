---
cairn: spec
capability: message-copy
---

# Message copy

## Requirements

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
