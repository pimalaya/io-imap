# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added streaming IMAP APPEND via `ImapClientStd::append_stream` and `ImapMessageAppendYield::WantsStream`.

  The coroutine yields `WantsStream` at the literal boundary so the driver pumps the declared message octets straight from its own source to the socket; the body never lands in memory whole. `append_stream(mailbox, source, len, opts)` takes any `Read` source plus its exact octet count (IMAP declares it up front). A short source poisons the connection and surfaces `ImapMessageAppendError::ShortMessage`.

- Added the `non_sync` option on `ImapMessageAppendOptions`.

  Sends a non-synchronising literal (`{N+}`) and streams the body without waiting for the server continuation (requires LITERAL+ / LITERAL-). Defaults to a synchronising `{N}` literal so the server can still reject before the body is sent.

- Added `SendImapCommand::receive`.

  Receive-only constructor that parses a response whose request bytes were written out of band; reused by the streamed APPEND literal.

### Changed

- Changed IMAP APPEND to keep the message body out of memory.

  `ImapMessageAppend::new` now takes the message octet count (`u32`) instead of a `LiteralOrLiteral8`, and returns the new `ImapMessageAppendYield` instead of the shared `ImapYield`. `ImapClientStd::append(mailbox, message, opts)` now takes the message as `&[u8]` (a buffered convenience that delegates to `append_stream`); both client methods take an `ImapMessageAppendOptions` carrying `flags` / `date` / `non_sync`.

## [0.1.0] - 2026-06-03

### Added

- Added the `ImapCoroutine` mirroring `core::ops::Coroutine`.

  The trait is composed of `Yield` and `Return` associated types, as well as a two-variant `ImapCoroutineState<Y, R>` (`Yielded(Y)` and `Complete(R)`). Standard coroutines pick the shared `ImapYield { WantsRead, WantsWrite(Vec<u8>) }`; coroutines that surface domain events declare their own Yield enum with an extra `Event(...)` variant.

- Added the `imap_try!` macro: coroutine equivalent of `?`.

  Advances one inner resume step, re-yields intermediate `Yielded(y)` (via `Into`), and short-circuits on `Complete(Err(_))`.

- Added I/O-free IMAP IDLE coroutine following RFC 2177.

  Yields `ImapIdleYield::Event(ImapIdleEvent)` on every unilateral untagged batch, refreshes every 29 s by default to survive middle-boxes that drop long-idle sockets.

- Added I/O-free IMAP ID coroutine following RFC 2971.

  Returns the server's identification parameters, or `ID NIL` when no parameters are passed.

- Added I/O-free IMAP4rev1 coroutines following RFC 3501.

  greeting, capability, login, logout, starttls, list, lsub, status, create, delete, rename, subscribe, unsubscribe, select, examine, close, check, expunge, fetch (range + single-message), search, store (echo + silent), copy, append, noop.

- Added I/O-free IMAP UNSELECT coroutine following RFC 3691.

  Closes the selected mailbox without expunging `\Deleted` messages.

- Added I/O-free IMAP APPENDUID-only coroutine following RFC 4315 (UIDPLUS).

  Lighter than `ImapMessageAppend`; drops the EXISTS count and surfaces only the `NonZeroU32` APPENDUID pair.

- Added I/O-free IMAP ENABLE coroutine following RFC 5161.

  Returns the server's `ENABLED` capability list.

- Added I/O-free IMAP SORT and THREAD coroutines following RFC 5256.

  Each supports the `UID` variant via its options struct.

- Added I/O-free IMAP MOVE coroutine following RFC 6851.

  Surfaces the optional `[COPYUID …]` triple when the server announces UIDPLUS.

- Added I/O-free SASL coroutines under `crate::sasl`: ANONYMOUS, LOGIN, PLAIN, XOAUTH2.

  Each supports both the non-IR and SASL-IR (RFC 4959) flows.

- Added I/O-free SASL OAUTHBEARER coroutine following RFC 7628.

  Supports both non-IR and SASL-IR flows.

- Added I/O-free SASL SCRAM-SHA-256 coroutine following RFC 7677, behind the `scram` cargo feature.

- Added the optional `auto_id` field on every auth/login coroutine.

  Applies to `ImapLogin`, `ImapAuthAnonymous`, `ImapAuthLogin`, `ImapAuthPlain`, `ImapAuthOauthbearer`, `ImapAuthXoauth2` and `ImapAuthScramSha256`. When set, chains an RFC 2971 `ID` round-trip immediately after the tagged auth response (empty vec sends `ID NIL`, non-empty sends `ID (key val …)`). Required by providers such as mail.qq.com and fastmail.

- Added the `ImapMailboxWatch` composite coroutine.

  Chains ENABLE QRESYNC, SELECT (CONDSTORE), FETCH 1:* baseline seed, IDLE wake-loop and SELECT (QRESYNC) delta pulls. Emits UID-keyed `EnvelopeAdded` / `FlagsAdded` / `FlagsRemoved` / `EnvelopeRemoved` events. Bails when the server does not advertise QRESYNC.

- Added the `client` cargo feature enabling `ImapClientStd::new(stream)`.

  Blocking light client wrapping any `Read + Write` stream with a per-connection `Fragmentizer` and exposing one method per IMAP coroutine.

- Added `ImapClientStd::watch_mailbox(self, mailbox, capability) -> ImapMailboxWatchStream`.

  Consumes the client, spawns a worker thread that drives `ImapMailboxWatch` over the socket, exposes events on a bounded mpsc channel. `close()` flips the shared shutdown atomic and joins the worker cleanly.

- Added the `rustls-ring` cargo feature (default) enabling `ImapClientStd::connect(url, tls, starttls, sasl, auto_id)`.

  Opens `imap://` (plain TCP) or `imaps://` (implicit TLS) via [pimalaya/stream](https://github.com/pimalaya/stream) with rustls + ring crypto provider, drives optional STARTTLS upgrade, reads greeting and capability, runs the chosen SASL mechanism, returns an authenticated client.

- Added the `rustls-aws` cargo feature.

  Same full client as `rustls-ring` but with the aws-lc-rs crypto provider.

- Added the `native-tls` cargo feature.

  Same full client backed by the platform's `native-tls` implementation.

- Added the `vendored` cargo feature.

  Compiles the underlying TLS dependencies in vendored mode (forwarded to `pimalaya-stream/vendored`).

[unreleased]: https://github.com/pimalaya/io-imap/compare/v0.1.0..HEAD
[0.1.0]: https://github.com/pimalaya/io-imap/compare/root..v0.1.0
