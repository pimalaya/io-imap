---
cairn: log
change: ci-and-supply-chain-hygiene
landed: 2026-11-03
---

# Live test logs and the dependency allow-list

- The app-password live tests stay at `RUST_LOG: trace`: since b1ab38e, LOGIN and AUTHENTICATE log only their tag and name, the SASL state messages carry no secret, and the rest of the trace is server bytes and host and port.
- The OAuth live tests stay at `RUST_LOG: debug` for another reason than their NOTE gave: io-http traces each request (`trace!("{req:?}")`), and the token request body carries the Microsoft client secret or the signed Google assertion. Both NOTEs now say so.
- deny.toml no longer allows the soywod/imap-codec git source (fd579d2); `allow-org.github = ["pimalaya"]` replaced it, which `cargo deny check sources` accepts with an `unmatched-organization` warning while no pimalaya git source is pinned.

No capability moved: CI and supply-chain configuration only.
