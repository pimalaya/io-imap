---
cairn: delta
change: uncopied-literals-and-incomplete-listings
---

## ADDED Requirements

### Requirement: An incomplete listing removes nothing

A whole-mailbox re-read whose FETCH skipped a line for not decoding SHALL report no removal and keep in the shadow the messages its snapshot misses, while still reporting the additions and flag changes it read. A QRESYNC reply that skipped a line SHALL apply what it read and keep its resync point, so the next resync asks again from it.

#### Scenario: One line of the re-read does not decode

- **WHEN** a watch knowing UIDs 1 and 2 re-reads a mailbox whose line for UID 1 is skipped and whose UID 2 is now `\Seen`
- **THEN** it emits the `\Seen` of 2 alone, and its state still holds UID 1

#### Scenario: One line of a QRESYNC reply does not decode

- **WHEN** a watch at resync point 42 reads a reply announcing `HIGHESTMODSEQ 50` and skips one of its FETCH lines
- **THEN** its state keeps the resync point 42

### Requirement: A literal is written uncopied

A send SHALL drop the command once it is encoded, and yield each literal as the payload of a write of its own, moved out of the encoded command: a line is never appended to a literal, nor a literal to a line. A buffered APPEND given a message it owns SHALL add no more than one copy of it to the heap, the one its encoder makes.

#### Scenario: Synchronising literal

- **WHEN** an APPEND of `hi` tagged `A1` reads `+ go`
- **THEN** it writes `hi`, then the line end in a second write

#### Scenario: Non-synchronising literal

- **WHEN** an APPEND of `hi` with a non-synchronising literal is given its tag
- **THEN** it writes the line ending in `{2+}`, `hi`, then the line end, in three writes and without reading

#### Scenario: Peak of a buffered APPEND

- **WHEN** a buffered APPEND of 8 MiB runs to its completion
- **THEN** the heap grows by less than 12 MiB at its peak

### Requirement: An error carries the first octets of a response

The errors holding a response that did not decode, poisoned the fragmentizer or exceeded its size limit, in a send, the greeting and IDLE, SHALL carry its first 1024 octets at most.

#### Scenario: Undecodable line of 64 KiB

- **WHEN** a send reads a tagged line of 64 KiB that does not decode
- **THEN** it fails with `DecodingFailure` holding the first 1024 octets of the line

### Requirement: A write shows its length only

The `Debug` of `ImapYield` and of `ImapSessionOpenYield` SHALL print the number of octets of a write, never the octets.

#### Scenario: LOGIN command

- **WHEN** the yield of the write `A1 LOGIN alice secret` is formatted for debugging
- **THEN** it reads `WantsWrite(23 octets)`

### Requirement: URL errors show scheme, host and port only

The errors of `ImapSessionTransport::from_url` SHALL hold and print the scheme, host and port of the URL, never its userinfo, path or query.

#### Scenario: Unsupported scheme with credentials

- **WHEN** `https://alice:hunter2@example.org:8443/inbox?token=abc` is read
- **THEN** the error reads ``IMAP URL `https://example.org:8443` has unsupported scheme `https` (expected `imap`, `imaps` or `unix`)``

### Requirement: A SCRAM exchange needs a client nonce

`ImapAuthScramSha256::new` SHALL fail with `EmptyNonce` on credentials carrying an empty client nonce, as SHALL a session opened with them. Only `ImapClientStd::connect` draws a nonce for credentials left without one.

#### Scenario: Empty nonce

- **WHEN** the coroutine is built from credentials whose nonce is empty
- **THEN** the constructor fails with `EmptyNonce`, and nothing is written

## MODIFIED Requirements

### Requirement: The bare core is no_std

Building io-imap without default features enables no `std` feature in its dependency tree, with the `scram` feature as without it. Only the `client` feature pulls std, including the imap-types tag generator `ImapClientStd` answers `WantsTag` with; the rand dependency that draws a SCRAM nonce comes with the TLS features, which compile the only code using it.

#### Scenario: Bare build

- **WHEN** io-imap is built with `--no-default-features`
- **THEN** no dependency has its `std` feature enabled

#### Scenario: SCRAM alone

- **WHEN** io-imap is built with `--no-default-features --features scram`
- **THEN** its dependency tree holds no rand
