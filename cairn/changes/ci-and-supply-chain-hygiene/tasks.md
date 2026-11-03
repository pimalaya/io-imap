---
cairn: tasks
change: ci-and-supply-chain-hygiene
---

# Tasks

- [ ] .github/workflows/tests.yml:25 and :43: `RUST_LOG: debug` (or redaction landed first), with a NOTE as at :46-47
- [ ] deny.toml:18: drop the soywod/imap-codec allow-git entry
- [ ] `cargo deny check sources` green
- [ ] Log; land
