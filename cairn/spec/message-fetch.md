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

### Requirement: A FETCH line keeps the items that decode

A send reading an untagged `* <number> FETCH (…)` message that does not decode SHALL split its top level into its items, a name and a value each, with a scanner counting the depth of parenthesised lists without recursion and taking quoted strings and literals whole, and SHALL decode each item alone. The items that decode SHALL join the command's data under the line's sequence number, as a whole line's would. The items that do not SHALL be returned in the output's `partial`, as an `ImapFetchPartial { seq, uid, failed }`: `uid` the line's `UID` when that item decoded, `failed` one `ImapFetchFailedItem { name, raw }` per failed item, its name as sent and its bytes. A line whose top level does not scan SHALL stay skipped whole.

#### Scenario: A body structure nested too deep

- **WHEN** a FETCH reads `* 7 FETCH (UID 34 FLAGS (\Seen) BODYSTRUCTURE <seven nested multiparts>)`, then its `OK`
- **THEN** its data holds message 7 with `UID 34` and `FLAGS (\Seen)`, and its `partial` holds `{seq: 7, uid: 34, failed: [BODYSTRUCTURE]}`

#### Scenario: An item holding a literal

- **WHEN** a FETCH reads `* 3 FETCH (UID 9 BODY[HEADER] {14}` and its 14 octets, then `FLAGS (OIB-Seen-[Gmail]/All Mail))`, then its `OK`
- **THEN** its data holds message 3 with `UID 9` and its header, and its `partial` names `FLAGS`

#### Scenario: A line that does not scan

- **WHEN** a FETCH reads `* 2 FETCH (UID 5 FLAGS (\Seen)`, its parenthesis never closed, then its `OK`
- **THEN** its output holds the line as skipped and no `partial` entry
