---
cairn: spec
capability: mailbox-watch
---

# Mailbox watch

## Requirements

### Requirement: IDLE reads what it is resumed with

While idling, the IDLE coroutine SHALL take the bytes it is resumed with, and yield the responses they complete as an event, before it acts on its `done` flag or its refresh timer. It SHALL yield no event for a read that completed no response.

#### Scenario: Notification arriving with the wakeup that ends the IDLE

- **WHEN** `done` is set and the coroutine is resumed with `* 5 EXISTS`
- **THEN** it yields an event holding the EXISTS, and writes `DONE` on the next resume

#### Scenario: Read ending inside a line

- **WHEN** the coroutine is resumed with `* 5 EXI`
- **THEN** it asks for another read, and yields the EXISTS once `STS` and the line end arrive

### Requirement: Data read while an IDLE ends is an event

The untagged responses read between `DONE` and its tagged completion SHALL be yielded as an event before the coroutine completes or, on a timer refresh, re-issues IDLE. A refresh whose `done` flag was set meanwhile completes instead of idling again.

#### Scenario: Message delivered during a refresh

- **WHEN** a refresh wrote `DONE` and reads `* 24 EXISTS`, then the tagged `OK`
- **THEN** the coroutine yields an event holding the EXISTS before asking for the tag of the next IDLE

### Requirement: IDLE handles a BYE and an undecodable line as a send does

A BYE read while idling SHALL end the coroutine with `ImapIdleError::Bye` carrying the server's text. An untagged response that does not decode SHALL be skipped.

#### Scenario: Autologout

- **WHEN** an idling coroutine reads `* BYE Autologout`
- **THEN** it fails with `Bye` and the text `Autologout`

#### Scenario: Undecodable untagged line

- **WHEN** an idling coroutine reads `* FLAGS (OIB-Seen-[Gmail]/All Mail)`, then `* 5 EXISTS`
- **THEN** it yields an event holding the EXISTS alone

### Requirement: The watch wakes on mailbox data only

The watcher SHALL end its IDLE and resync only on an event holding mailbox data: EXISTS, EXPUNGE, FETCH or VANISHED. Any other untagged response, a keepalive status among them, leaves it idling.

#### Scenario: Keepalive

- **WHEN** an idling watch reads `* OK Still here`
- **THEN** it asks for another read without writing `DONE`

#### Scenario: Message delivered during a refresh

- **WHEN** the IDLE of a watch is refreshed and `* 2 EXISTS` precedes the completion of `DONE`
- **THEN** the watch resyncs and emits the new message

### Requirement: The baseline is fetched by UID

The watcher SHALL read the UIDs and flags of its mailbox with `UID FETCH 1:* (UID FLAGS)`, `*` as a sequence number being an error on an empty mailbox (RFC 3501 section 9).

#### Scenario: Baseline

- **WHEN** a watch has examined its mailbox
- **THEN** it writes `UID FETCH 1:* (UID FLAGS)`

### Requirement: A watch resumes from the state of a previous one

A watch SHALL hand out what it knows of its mailbox once its baseline is taken: the UIDVALIDITY, the QRESYNC resync point and the flags of every known message by UID. A watch given such a state SHALL skip the baseline and start at the resync step, emitting what changed since, and end with `UidValidityChanged` when the mailbox was recreated meanwhile.

#### Scenario: Resumed without QRESYNC

- **WHEN** a watch resumed from UIDs 1 and 2 reads a mailbox holding UID 2 flagged `\Seen` and UID 3
- **THEN** it emits the removal of 1, the `\Seen` of 2 and the addition of 3

#### Scenario: Resumed with QRESYNC

- **WHEN** a watch is resumed from UIDVALIDITY 1700 and resync point 42
- **THEN** after ENABLE it writes `EXAMINE INBOX (QRESYNC (1700 42))`, and emits what the reply reports
