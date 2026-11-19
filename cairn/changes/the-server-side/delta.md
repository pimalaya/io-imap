---
cairn: delta
change: the-server-side
---

## ADDED Requirements

### Requirement: The session frames, then hands out commands in order

See cairn/spec/server-session.md, folded whole: the capability is new, with its requirements on command order, state tracking, authentication up to the verdict, plaintext credentials waiting for TLS, ENABLE, IDLE, and bounded literals and lines.

#### Scenario: Pipelined commands

- **WHEN** a client sends `1 LOGIN`, `2 SELECT`, `3 NOOP` and `4 CHECK` in one read
- **THEN** the session writes their completions tagged 1, 2, 3, 4 in that order

## MODIFIED Requirements

### Requirement: The bare core is no_std

Building io-imap without default features enables no `std` feature in its dependency tree, with the `client`, `server` and `scram` features as without them. Only the `std` feature pulls std, including the imap-types tag generator `ImapClientStd` answers `WantsTag` with; the rand dependency that draws a SCRAM nonce comes with the TLS features, which compile the only code using it.

#### Scenario: Coroutines and server session

- **WHEN** io-imap is built with `--no-default-features --features client,server`
- **THEN** no dependency has its `std` feature enabled
