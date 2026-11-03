---
cairn: delta
change: hostile-server-hardening
---

## ADDED Requirements

### Requirement: An exchange ends on its own command's completion

A send ends only on the tagged completion carrying the tag of the command it belongs to: the tag it was answered with, or the tag of the command a continuation or IDLE DONE belongs to. A tagged completion with another tag is skipped.

#### Scenario: Foreign completion first

- **WHEN** a send for the command tagged `A1` reads `B9 NO not yours`, then `A1 OK`
- **THEN** it keeps reading after `B9`, and completes with the `A1 OK` status

### Requirement: VANISHED (EARLIER) stays as ranges

SELECT and EXAMINE report a `VANISHED (EARLIER)` uid-set as the inclusive ranges the server announced, never expanded, and the mailbox watch removes the UIDs it holds within each range.

#### Scenario: Whole UID space announced

- **WHEN** a SELECT response carries `* VANISHED (EARLIER) 1:4294967295`
- **THEN** the select data holds the single range `1..=4294967295`
