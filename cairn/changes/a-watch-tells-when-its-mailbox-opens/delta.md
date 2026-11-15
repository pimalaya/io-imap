---
cairn: delta
change: a-watch-tells-when-its-mailbox-opens
---

# Delta

## ADDED Requirements

### Requirement: A watch tells when its mailbox is open

(mailbox-watch) `ImapMailboxWatch::opened` SHALL be false until an EXAMINE of the watch succeeds and passes the watch's checks (UIDVALIDITY present, HIGHESTMODSEQ present on the QRESYNC path, UIDVALIDITY unchanged on a resume), and true from then on. An ENABLE alone SHALL NOT open the watch.

#### Scenario: Examined

- **WHEN** a watch reads the `OK` of its EXAMINE, with a UIDVALIDITY
- **THEN** `opened` is true when it writes its baseline FETCH

#### Scenario: Refused

- **WHEN** a watch, new or resumed, with or without QRESYNC, reads `NO` to its EXAMINE
- **THEN** it fails with `Examine` and `opened` stays false

#### Scenario: Recreated mailbox

- **WHEN** a resumed watch reads an EXAMINE announcing another UIDVALIDITY
- **THEN** it fails with `UidValidityChanged` and `opened` stays false

### Requirement: The watch stream tells when its mailbox is open

(std-client) The worker of `ImapClientStd::watch_mailbox` SHALL signal the opening of its watch once, before handing over what the resume that opened it yielded. `ImapMailboxWatchStream::wait_opened` SHALL return `Ok(())` once the watch is open, `Timeout` while it is not yet, and `Disconnected` when the worker ended without opening it, its error then waiting on the stream. `ImapMailboxWatchStream::opened` SHALL tell the same without waiting.

#### Scenario: Examined

- **WHEN** the server answers the EXAMINE of the watch with `OK` and a UIDVALIDITY
- **THEN** `wait_opened` returns `Ok(())`

#### Scenario: Refused

- **WHEN** the server answers the EXAMINE of the watch with `NO`
- **THEN** `wait_opened` returns `Disconnected`, and the stream yields the refusal
