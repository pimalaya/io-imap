---
cairn: delta
change: only-what-enabled-lists-is-enabled
---

# Delta

## ADDED Requirements

### Requirement: Only what ENABLED lists is enabled

(mailbox-watch) An extension SHALL count as enabled only when the untagged `ENABLED` answering the ENABLE names it (RFC 5161 section 3.2). A watch whose server advertises QRESYNC SHALL take the QRESYNC path only when that `ENABLED` names QRESYNC, and the whole-mailbox fallback otherwise: a plain `EXAMINE`, then `UID FETCH 1:* (UID FLAGS)` diffed against its shadow, on every wake. CONDSTORE named alone SHALL NOT open the QRESYNC path.

#### Scenario: ENABLE answered by a bare OK

- **WHEN** a watch of a server advertising QRESYNC reads `OK` to its ENABLE with no `ENABLED`, takes its baseline, and is woken by `* 2 EXISTS`
- **THEN** it writes `EXAMINE INBOX` without parameters then `UID FETCH 1:* (UID FLAGS)`, and emits the added message

#### Scenario: ENABLED names CONDSTORE alone

- **WHEN** a watch of a server advertising QRESYNC reads `* ENABLED CONDSTORE` to its ENABLE
- **THEN** it watches the whole mailbox, as on a bare `OK`

#### Scenario: Resumed watch whose ENABLE lists nothing

- **WHEN** a watch resumed from resync point 225 reads `OK` to its ENABLE with no `ENABLED`
- **THEN** it writes `EXAMINE INBOX` without parameters, not `EXAMINE INBOX (QRESYNC (1700 225))`, and emits what its re-read finds

## MODIFIED Requirements

### Requirement: A watch resumes from the state of a previous one

(mailbox-watch) A watch SHALL hand out what it knows of its mailbox once its baseline is taken: the UIDVALIDITY, the QRESYNC resync point and the flags of every known message by UID. A watch given such a state SHALL skip the baseline and start at the resync step, emitting what changed since, and end with `UidValidityChanged` when the mailbox was recreated meanwhile.

#### Scenario: Resumed without QRESYNC

- **WHEN** a watch resumed from UIDs 1 and 2 reads a mailbox holding UID 2 flagged `\Seen` and UID 3
- **THEN** it emits the removal of 1, the `\Seen` of 2 and the addition of 3

#### Scenario: Resumed with QRESYNC

- **WHEN** a watch is resumed from UIDVALIDITY 1700 and resync point 42
- **THEN** after an ENABLE answered with `* ENABLED QRESYNC` it writes `EXAMINE INBOX (QRESYNC (1700 42))`, and emits what the reply reports

## REMOVED Requirements

None.
