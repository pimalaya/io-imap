---
cairn: spec
capability: message-fetch
---

# Message fetch

## Requirements

### Requirement: A single-message FETCH returns the requested message

`ImapMessageFetchFirst` SHALL return the items of the FETCH responses for the message it asked for, matched by sequence number, or by their `UID` item in UID mode, and fail with `MissingData` when there is none. A FETCH response for another message, which a server may send at any time (RFC 3501 section 7.4.2), is left out.

#### Scenario: Flag change of another message

- **WHEN** a UID FETCH of UID 42 reads `* 7 FETCH (UID 42)`, then `* 9 FETCH (FLAGS (\Seen))`
- **THEN** it returns the `UID 42` item alone
