---
cairn: log
change: coroutine-tag-yield
landed: 2026-11-03
---

# Coroutines ask their caller for command tags

- `ImapYield::WantsTag` and `ImapSend::command(body)`: the send yields `WantsTag`, validates the answer as a `Tag` and fails with `ImapSendError::MissingTag` or `InvalidTag`. Every coroutine dropped `TagGenerator`; the fetch streams, the streamed APPEND and STARTTLS, which encode their command themselves, carry their own tag step.
- Every yield type built on `ImapYield` carries `WantsTag`. `ImapClientStd` answers it from its new `tags` field (also used by `connect` and `watch_mailbox`); examples, integration tests and module docs answer it.
- Composites now pass `arg.take()` to their sub-coroutines. Passing the same bytes to a freshly started one was harmless while `ImapSend` ignored its first input, but would have read an AUTHENTICATE reply as the tag of the chained CAPABILITY (guarded by `sasl::auth_plain::tests::ir_success_without_capability_fetches_capability`, which fails without the fix).
- `imap-codec/tag_generator` is enabled by `client` only: `cargo tree --no-default-features` shows no `std` feature, closing [pimalaya/io-imap#4](https://github.com/pimalaya/io-imap/issues/4).

Capabilities moved: `coroutines` (new spec file).
