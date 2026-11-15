---
cairn: delta
change: notify-watches-every-mailbox
---

# Delta

## ADDED Requirements

### Requirement: A BADEVENT refusal names its events

(mailbox-notify) A NOTIFY answered `NO` with a `BADEVENT` code SHALL fail with `ImapNotifySetError::BadEvent`, carrying the event names the code lists, whether they are parenthesised (RFC 5465) or not (Dovecot). Any other `NO` SHALL fail with `No`.

#### Scenario: RFC form

- **WHEN** a NOTIFY reads `A1 NO [BADEVENT (MessageNew MessageExpunge XFoo)] Unsupported`
- **THEN** it fails with `BadEvent` naming `MessageNew`, `MessageExpunge` and `XFoo`

#### Scenario: Dovecot's form

- **WHEN** a NOTIFY reads `A1 NO [BADEVENT AnnotationChange ServerMetadataChange] Unsupported NOTIFY events.`
- **THEN** it fails with `BadEvent` naming `AnnotationChange` and `ServerMetadataChange`

### Requirement: A NOTIFY watch yields what the server reports

(mailbox-notify) `ImapNotifyWatch` SHALL send its NOTIFY, then hold IDLE, and yield every batch of untagged responses as an event: first the data read with the NOTIFY completion, then what IDLE reads. `opened` SHALL be false until the NOTIFY is accepted.

#### Scenario: Status first

- **WHEN** a watch with `SET STATUS` reads `* STATUS INBOX (MESSAGES 2 UIDNEXT 3)` and the NOTIFY completion
- **THEN** it yields an event holding that STATUS, then writes `IDLE`

#### Scenario: Notification while idling

- **WHEN** an idling watch reads `* STATUS Lists (MESSAGES 3 UIDNEXT 9)`
- **THEN** it yields an event holding it and keeps idling

#### Scenario: Refused

- **WHEN** a watch reads `NO [BADEVENT …]` to its NOTIFY
- **THEN** it fails with `Notify(BadEvent)` and `opened` stays false

### Requirement: A NOTIFY watch enables CONDSTORE first

(mailbox-notify) With `ImapNotifyCondstore::Prefer` (the default) or `Require`, and capabilities that include ENABLE and CONDSTORE, `ImapNotifyWatch` SHALL send `ENABLE CONDSTORE` before its NOTIFY, and `condstore` SHALL be true only when the server's ENABLED lists CONDSTORE (RFC 5161 section 3.2), as for the mailbox watch. A failed ENABLE SHALL end the watch with `Enable`. With `Require`, capabilities that lack either SHALL fail it with `CondstoreNotSupported` before sending anything, and an ENABLED that doesn't list CONDSTORE SHALL fail it the same way.

#### Scenario: Enabled

- **WHEN** the ENABLE reads `* ENABLED CONDSTORE` and `OK`
- **THEN** the watch sends its NOTIFY and `condstore` is true

#### Scenario: Refused

- **WHEN** the ENABLE reads `BAD`
- **THEN** the watch fails with `Enable(Bad)`

#### Scenario: ENABLED omits it

- **WHEN** the ENABLE reads a bare `OK`, or `* ENABLED` with nothing listed
- **THEN** with `Prefer` the watch sends its NOTIFY and `condstore` is false, and with `Require` it fails with `CondstoreNotSupported`

#### Scenario: Not advertised

- **WHEN** the capabilities lack ENABLE or CONDSTORE
- **THEN** with `Prefer` the first command is the NOTIFY, and with `Require` the watch fails with `CondstoreNotSupported`

#### Scenario: Disabled

- **WHEN** the options set `Disable`
- **THEN** the first command is the NOTIFY

### Requirement: An overflow ends a NOTIFY watch

(mailbox-notify) An event holding a `NOTIFICATIONOVERFLOW` code SHALL be yielded, and the watch SHALL then end with `ImapNotifyWatchError::Overflow`, the server having stopped notifying.

#### Scenario: Overflow

- **WHEN** an idling watch reads `* OK [NOTIFICATIONOVERFLOW] too many`
- **THEN** it yields an event holding it, and the next resume fails with `Overflow`
