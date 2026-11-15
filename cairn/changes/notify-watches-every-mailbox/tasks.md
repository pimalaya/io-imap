---
cairn: tasks
change: notify-watches-every-mailbox
---

# Tasks

- [x] Cargo.toml: `ext_notify`, imap-codec patched to the NOTIFY branch
- [x] src/rfc5465/notify.rs: `ImapNotifySet`, `BadEvent` in both forms (`rfc5465::notify::tests`)
- [x] src/rfc5465/watch.rs: `ImapNotifyWatch`, `opened`, `Overflow` (`rfc5465::watch::tests`)
- [x] src/client.rs: `notify`, `watch_notify`, `ImapNotifyWatchStream`, error status and connection loss (`client::tests::a_notify_stream_*`)
- [x] README, CHANGELOG under [Unreleased], crate docs
- [x] Tried against Dovecot 2.4.5
- [x] ENABLE CONDSTORE first, `ImapNotifyCondstore` Disable/Prefer/Require (`rfc5465::watch::tests::*condstore*`, `*enable*`, `require_*`)
- [ ] imap-codec#750 released; drop the patch and bump imap-codec
- [ ] Fold the delta into cairn/spec, log, land
