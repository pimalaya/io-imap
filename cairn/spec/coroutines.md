---
cairn: spec
capability: coroutines
---

# Coroutines

## Requirements

### Requirement: Command tags come from the caller

A coroutine never generates a command tag. Before writing each tagged command, it yields `WantsTag` and builds the command from the tag the caller resumes it with. A composite starts each sub-coroutine with no input, so bytes answering one command are never read as the next command's tag.

#### Scenario: Tag answered

- **WHEN** a coroutine yields `WantsTag` and is resumed with `A1`
- **THEN** it yields `WantsWrite` with a command tagged `A1`

#### Scenario: Tag missing or invalid

- **WHEN** a coroutine yields `WantsTag` and is resumed with nothing, or with bytes that are not a valid tag
- **THEN** it completes with `MissingTag` or `InvalidTag`

#### Scenario: Chained command

- **WHEN** a composite's command completes on the bytes the caller resumed it with, and the composite chains another command
- **THEN** it yields `WantsTag` for that command instead of reading those bytes as its tag

### Requirement: The bare core is no_std

Building io-imap without default features enables no `std` feature in its dependency tree. Only the `client` feature pulls std, including the imap-types tag generator `ImapClientStd` answers `WantsTag` with.

#### Scenario: Bare build

- **WHEN** io-imap is built with `--no-default-features`
- **THEN** no dependency has its `std` feature enabled
