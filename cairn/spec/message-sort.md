---
cairn: spec
capability: message-sort
---

# Message sort

## Requirements

### Requirement: The client-side sort follows RFC 5256

`ImapMessageSort` with `fallback` set SHALL order the searched messages as a server SORT would (RFC 5256 section 3): `SUBJECT` by the base subject (section 2.1, encoded words decoded), `FROM`, `TO` and `CC` by the `addr-mailbox` of the first address of the list (group markers skipped), `DATE` by the `Date:` instant or, when it cannot be parsed, the internal date, `ARRIVAL` by the internal date and `SIZE` by the size. Strings SHALL compare under `i;ascii-casemap`, a missing one being empty. Messages equal on every criterion SHALL keep their sequence order, which `REVERSE` does not flip. The RFC 5957 `DISPLAYFROM` and `DISPLAYTO` keys are not sorted on.

#### Scenario: Reply prefixes and encoded words

- **WHEN** the fallback sorts by `SUBJECT` the subjects `Bravo two`, `Re: echo thread start`, `=?UTF-8?B?Q2Fmw6kgZMOpasOgIHZ1?= charlie` and `[list] alpha (fwd)`
- **THEN** the order is alpha, Bravo, Café, echo

#### Scenario: Ties under REVERSE

- **WHEN** the fallback sorts by `REVERSE FROM` messages 1 to 4 from `alice`, `bob`, `ALICE` and `bob`
- **THEN** the order is 2, 4, 1, 3

### Requirement: The base subject is extracted in linear work

Extracting the base subject for the client-side sort SHALL take work linear in the length of the subject.

#### Scenario: Subject made of blobs

- **WHEN** the base subject of 1000 `[a]` blobs followed by `x` is extracted
- **THEN** it is `x`, after at most 3000 blob strips

### Requirement: The client-side sort returns searched messages only

The SORT fallback SHALL return only the ids its SEARCH matched, whatever other FETCH responses arrive while it fetches the sort keys.

#### Scenario: FETCH of an unmatched message

- **WHEN** the search matched UIDs 1 and 2, and the key FETCH also reads `* 3 FETCH (UID 3 FLAGS (\Seen))`
- **THEN** the sorted ids hold 1 and 2 only
