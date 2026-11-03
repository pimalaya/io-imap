---
cairn: tasks
change: coroutine-tag-yield
---

# Tasks

- [x] src/coroutine.rs: `ImapYield::WantsTag`
- [x] src/send.rs: `ImapSend::command`, tag step, `MissingTag` and `InvalidTag`
- [x] Every coroutine: `ImapSend::command(body)` instead of `TagGenerator`, unit tests answer `WantsTag`
- [x] Yield enums (session, idle, watch, append and fetch streams): `WantsTag`
- [x] src/client.rs and the async client: answer `WantsTag` from an owned `TagGenerator`
- [x] Cargo.toml: `imap-codec/tag_generator` only under `client`
- [x] Examples, integration tests and module docs answer `WantsTag`
- [x] `cargo tree --no-default-features` enables no `std` feature
- [x] CHANGELOG, fold the delta into spec, log, land (issue #4 closes on push, by the maintainer)
