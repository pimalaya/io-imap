---
cairn: delta
change: a-message-fetched-in-part-is-missing-data
---

# Delta

## MODIFIED Requirements

### Requirement: A single-message FETCH returns the requested message

(message-fetch) `ImapMessageFetchFirst` SHALL return the items of the FETCH responses for the message it asked for, matched by sequence number, or by their `UID` item in UID mode, and fail with `MissingData` when there is none. It SHALL also fail with `MissingData` when a FETCH response for that message was recovered in part, matched by the `seq` of its `partial` entry, or by its `uid` in UID mode. A FETCH response for another message, which a server may send at any time (RFC 3501 section 7.4.2), is left out, whether it decoded whole or in part.

#### Scenario: Flag change of another message

- **WHEN** a UID FETCH of UID 42 reads `* 7 FETCH (UID 42)`, then `* 9 FETCH (FLAGS (\Seen))`
- **THEN** it returns the `UID 42` item alone

#### Scenario: The requested envelope does not decode

- **WHEN** a UID FETCH of UID 42 reads `* 7 FETCH (UID 42 FLAGS (\Seen) ENVELOPE (NIL))`, then its `OK`
- **THEN** it fails with `MissingData`
