---
cairn: change
id: coroutine-tag-yield
status: landed
created: 2026-11-03
---

# Coroutines ask their caller for command tags

## Why

io-imap is `#![no_std]`, yet it still pulls std through imap-codec's `tag_generator` feature (imap-types `TagGenerator` needs rand's `thread_rng`), because every coroutine generates its own tags ([pimalaya/io-imap#4](https://github.com/pimalaya/io-imap/issues/4)). imap-types and imap-codec are no_std since 2.0.0-alpha.8 and 2.0.0-alpha.10, so this is the last std leak of the bare core.

Composites need several tags (session, SASL with CAPABILITY and ID, SORT fallback) and IDLE and the mailbox watch an unbounded number, so a tag passed to the constructor does not cover them.

## What

- `ImapYield` gains `WantsTag`: before each tagged command, the coroutine yields it and the caller resumes with the tag bytes. Every yield enum built on `ImapYield` carries the variant.
- `ImapSend::command(body)` starts in a tag step, validates the answered bytes as a `Tag` and builds `Command { tag, body }` from it. A missing or invalid tag fails with `ImapSendError::MissingTag` or `ImapSendError::InvalidTag`.
- Coroutines stop calling `TagGenerator`; their constructors are unchanged.
- The std clients answer `WantsTag` with an imap-types `TagGenerator` they own. `imap-codec/tag_generator` moves into the `client` feature, so `--no-default-features` pulls no std.

Breaking: every manual resume loop handles one more yield variant.
