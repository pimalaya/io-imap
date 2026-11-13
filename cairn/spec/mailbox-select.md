---
cairn: spec
capability: mailbox-select
---

# Mailbox select

## Requirements

### Requirement: VANISHED (EARLIER) stays as ranges

SELECT and EXAMINE report a `VANISHED (EARLIER)` uid-set as the inclusive ranges the server announced, never expanded, and the mailbox watch removes the UIDs it holds within each range.

#### Scenario: Whole UID space announced

- **WHEN** a SELECT response carries `* VANISHED (EARLIER) 1:4294967295`
- **THEN** the select data holds the single range `1..=4294967295`

### Requirement: SELECT and EXAMINE report how the mailbox was opened

The data of a SELECT or EXAMINE SHALL say whether the mailbox was opened read-only (`READ-ONLY` or `READ-WRITE` code of the completion, unknown when neither) and whether it keeps no modification sequences (`NOMODSEQ` code).

#### Scenario: Read-write mailbox without modification sequences

- **WHEN** a SELECT reads `* OK [NOMODSEQ] ...`, then `OK [READ-WRITE] SELECT completed`
- **THEN** its data says not read-only, and no modification sequences
