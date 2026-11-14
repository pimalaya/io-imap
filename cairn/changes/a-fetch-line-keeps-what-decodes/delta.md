---
cairn: delta
change: a-fetch-line-keeps-what-decodes
---

# Delta

## ADDED Requirements

### Requirement: A FETCH line keeps the items that decode

(message-fetch) A send reading an untagged `* <number> FETCH (…)` message that does not decode SHALL split its top level into its items, a name and a value each, with a scanner counting the depth of parenthesised lists without recursion and taking quoted strings and literals whole, and SHALL decode each item alone. The items that decode SHALL join the command's data under the line's sequence number, as a whole line's would. The items that do not SHALL be returned in the output's `partial`, as an `ImapFetchPartial { seq, uid, failed }`: `uid` the line's `UID` when that item decoded, `failed` one `ImapFetchFailedItem { name, raw }` per failed item, its name as sent and its bytes. A line whose top level does not scan SHALL stay skipped whole.

#### Scenario: A body structure nested too deep

- **WHEN** a FETCH reads `* 7 FETCH (UID 34 FLAGS (\Seen) BODYSTRUCTURE <seven nested multiparts>)`, then its `OK`
- **THEN** its data holds message 7 with `UID 34` and `FLAGS (\Seen)`, and its `partial` holds `{seq: 7, uid: 34, failed: [BODYSTRUCTURE]}`

#### Scenario: An item holding a literal

- **WHEN** a FETCH reads `* 3 FETCH (UID 9 BODY[HEADER] {14}` and its 14 octets, then `FLAGS (OIB-Seen-[Gmail]/All Mail))`, then its `OK`
- **THEN** its data holds message 3 with `UID 9` and its header, and its `partial` names `FLAGS`

#### Scenario: A line that does not scan

- **WHEN** a FETCH reads `* 2 FETCH (UID 5 FLAGS (\Seen)`, its parenthesis never closed, then its `OK`
- **THEN** its output holds the line as skipped and no `partial` entry

## MODIFIED Requirements

### Requirement: A skipped response is kept

(coroutines) A send SHALL keep the raw bytes of every untagged response it skipped for not decoding, in its output, counted against its budget. A `FETCH` response recovered in part (message-fetch, "A FETCH line keeps the items that decode") SHALL NOT be skipped.

#### Scenario: Undecodable FLAGS line

- **WHEN** a send reads `* FLAGS (OIB-Seen-[Gmail]/All Mail)`, then its `OK`
- **THEN** it completes, and its output holds that line as skipped

### Requirement: A command returning data returns what its response held beside it

(coroutines) FETCH over a sequence set, STORE, SEARCH, SORT, THREAD, STATUS, LIST, LSUB, EXPUNGE, UID EXPUNGE, SELECT, EXAMINE, NOOP and CHECK SHALL complete with an output holding their result, the texts of the `ALERT` response codes read in the untagged status responses and in the completion, the untagged responses skipped for not decoding, and the `FETCH` responses recovered in part. The client-side SORT SHALL add up those of its SEARCH and of each of its FETCH commands. The mailbox watcher SHALL take a snapshot as complete only when nothing was skipped and no response recovered in part failed `UID`, `FLAGS` or `MODSEQ`.

#### Scenario: One FETCH line does not decode

- **WHEN** a FETCH reads `* 1 FETCH (FLAGS (\Seen))`, `* 2 FETCH (FLAGS (OIB-Seen-[Gmail]/All Mail))`, `* OK [ALERT] quota almost reached`, then its `OK`
- **THEN** its output holds the data of message 1, message 2 in `partial` with `FLAGS` failed, and the alert `quota almost reached`

#### Scenario: Client-side SORT

- **WHEN** the SEARCH of a client-side SORT skips one line and its FETCH another
- **THEN** the output of the SORT holds both lines as skipped

## REMOVED Requirements

None.
