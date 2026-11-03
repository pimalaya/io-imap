---
cairn: tasks
change: ci-and-supply-chain-hygiene
---

# Tasks

- [x] .github/workflows/tests.yml:25 and :43: kept at trace, since the redaction landed first (b1ab38e: LOGIN and AUTHENTICATE log only their tag and name); the OAuth steps' NOTEs reworded, debug being kept because io-http traces the token request
- [x] deny.toml:18: soywod/imap-codec entry dropped (fd579d2), replaced by `allow-org.github = ["pimalaya"]`
- [x] `cargo deny check sources` green (one `unmatched-organization` warning while no pimalaya git source is pinned)
- [x] Log; land
