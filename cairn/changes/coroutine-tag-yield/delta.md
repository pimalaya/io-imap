---
cairn: delta
change: coroutine-tag-yield
---

## ADDED Requirements

### Requirement: Command tags come from the caller

A coroutine never generates a command tag. Before writing each tagged command, it yields `WantsTag` and builds the command from the tag the caller resumes it with.

#### Scenario: Tag answered

- **WHEN** a coroutine yields `WantsTag` and is resumed with `A1`
- **THEN** it yields `WantsWrite` with a command tagged `A1`

#### Scenario: Tag missing or invalid

- **WHEN** a coroutine yields `WantsTag` and is resumed with nothing, or with bytes that are not a valid tag
- **THEN** it completes with `MissingTag` or `InvalidTag`

### Requirement: The bare core is no_std

Building io-imap without default features enables no `std` feature in its dependency tree. Only the `client` feature pulls std, including the tag generator the std clients answer `WantsTag` with.

#### Scenario: Bare build

- **WHEN** io-imap is built with `--no-default-features`
- **THEN** no dependency has its `std` feature enabled
