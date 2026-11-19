---
cairn: tasks
change: the-server-side
---

# Tasks

- [x] Cargo.toml: `std`, `client`, `server` features; io-sasl `client`/`server`; chrono, mime-rs and base64-codec optional under `client`; io-sasl patched to ../io-sasl
- [x] src/lib.rs: client modules under `client`, `client` module under `std`, `server` module under `server`
- [x] src/rfc2177/idle.rs, src/watch.rs: the IDLE refresh timer gated on `std`
- [x] src/server.rs: `ImapServerSession` and companions
- [x] tests/server.rs: RFC replays, client coroutines against the session, literals, limits
- [x] fuzz/fuzz_targets/server.rs: 60 s smoke run clean
- [x] CHANGELOG.md, README.md, CONTRIBUTING.md, fuzz/README.md
- [x] spec: server-session added, coroutines no_std requirement modified
- [ ] io-sasl `client`/`server` features released, then the `[patch.crates-io]` entries dropped (Cargo.toml, fuzz/Cargo.toml)
