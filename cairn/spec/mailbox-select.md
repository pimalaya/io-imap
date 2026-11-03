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
