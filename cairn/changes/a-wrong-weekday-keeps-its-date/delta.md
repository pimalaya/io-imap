---
cairn: delta
change: a-wrong-weekday-keeps-its-date
---

# Delta

## ADDED Requirements

None.

## MODIFIED Requirements

### Requirement: The client-side sort follows RFC 5256

(message-sort) `ImapMessageSort` with `fallback` set SHALL order the searched messages as a server SORT would (RFC 5256 section 3): `SUBJECT` by the base subject (section 2.1, encoded words decoded), `FROM`, `TO` and `CC` by the `addr-mailbox` of the first address of the list (group markers skipped), `DATE` by the `Date:` instant, its day-of-week ignored (RFC 5322 section 3.3), or, when it cannot be parsed, the internal date, `ARRIVAL` by the internal date and `SIZE` by the size. Strings SHALL compare under `i;ascii-casemap`, a missing one being empty. Messages equal on every criterion SHALL keep their sequence order, which `REVERSE` does not flip. The RFC 5957 `DISPLAYFROM` and `DISPLAYTO` keys are not sorted on.

#### Scenario: Reply prefixes and encoded words

- **WHEN** the fallback sorts by `SUBJECT` the subjects `Bravo two`, `Re: echo thread start`, `=?UTF-8?B?Q2Fmw6kgZMOpasOgIHZ1?= charlie` and `[list] alpha (fwd)`
- **THEN** the order is alpha, Bravo, Café, echo

#### Scenario: Ties under REVERSE

- **WHEN** the fallback sorts by `REVERSE FROM` messages 1 to 4 from `alice`, `bob`, `ALICE` and `bob`
- **THEN** the order is 2, 4, 1, 3

#### Scenario: Wrong day-of-week

- **WHEN** the fallback sorts by `DATE` messages 1 and 2 dated `Thu, 01 Jan 2026 08:00:00 +0000` and `Thu, 01 Jan 2026 12:00:00 +0000`, and message 3, arrived on 3 January, dated `Mon, 01 Jan 2026 06:00:00 +0000` (a Thursday)
- **THEN** the order is 3, 1, 2

## REMOVED Requirements

None.
