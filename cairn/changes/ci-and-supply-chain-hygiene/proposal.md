---
cairn: change
id: ci-and-supply-chain-hygiene
status: active
created: 2026-10-18
---

# Live test logs and the dependency allow-list

## Why

Two hygiene items left open, each re-checked against the repository on 2026-10-18.

- **Trace logs next to app passwords.** .github/workflows/tests.yml sets `RUST_LOG: trace` for the fastmail-tests job (line 25) and the password step of gmail-tests (line 43), while lines 27 and 45 hand those steps an app password. At trace level the client logs every byte it reads and writes, so a password GitHub fails to mask (escaped, split or re-encoded) can land in a public CI log. The OAuth steps already run at debug for that reason (lines 46-50 and 67-71).
- **Stale allow-git entry.** deny.toml:15-19 still allows https://github.com/soywod/imap-codec (line 18), while Cargo.lock:623-627 resolves imap-codec 2.0.0-alpha.9 from crates.io. The entry no longer serves anything and would let a git source back in unreviewed.

## What

- Lower both password steps to `RUST_LOG: debug`, with the same NOTE the OAuth steps carry; or keep trace once the client redacts LOGIN and AUTHENTICATE payloads in its trace output.
- Drop the soywod/imap-codec line from `[sources] allow-git`, leaving the list empty (the commented pimalaya/stream line can go too).

No behaviour of the library moves, so there is no delta.
