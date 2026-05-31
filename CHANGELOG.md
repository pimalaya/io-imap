# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added basic I/O-free coroutines.

- Added standard, blocking client.

- Added the `crate::watch::ImapMailboxWatch` I/O-free coroutine: composes `SELECT (CONDSTORE)`, `FETCH 1:* (UID FLAGS)`, `ImapIdle` and `SELECT (QRESYNC ...)` into a single state machine that emits `ImapMailboxWatchEvent::EnvelopeAdded` / `FlagsAdded` / `FlagsRemoved` / `EnvelopeRemoved` events. Requires server-side QRESYNC; bails otherwise.

- Added `ImapClientStd::watch_mailbox(self, mailbox) -> ImapMailboxWatchStream`: consumes the client, spawns a background thread that drives `ImapMailboxWatch` over the socket, and returns an `Iterator` of events backed by a bounded mpsc channel. `close()` flips the shared shutdown atomic and joins the worker cleanly.

### Changed

- Added an `auto_id: Option<Vec<(IString<'static>, NString<'static>)>>` constructor argument to every auth coroutine (`ImapLogin`, `ImapAuthAnonymous`, `ImapAuthLogin`, `ImapAuthPlain`, `ImapAuthOAuthBearer`, `ImapAuthXOAuth2`, `ImapAuthScramSha256`). When `Some`, the coroutine chains an RFC 2971 `ID` round-trip after the tagged auth response (empty vec → `ID NIL`, non-empty → `ID (key val …)`); each error enum gained a `ServerId(#[from] ImapServerIdError)` variant. `ImapClientStd` gained a matching `pub auto_id` field consumed by every `auth_*`/`login` method (moved into the coroutine then reset to `None`). `ImapClientStd::connect` takes the same `auto_id` argument and threads it through the SASL dispatch so providers that require `ID` after auth (mail.qq.com, fastmail) are reachable end-to-end.

- Flattened `ImapIdleDone` into a plain `Arc<AtomicBool>`: `ImapIdle::new` now takes `done: Arc<AtomicBool>` directly. Callers use `done.store(true, Ordering::SeqCst)` / `done.load(Ordering::SeqCst)` instead of the wrapper's `done()` / `is_done()` methods.

- Unified all standard-shape coroutines under a single `ImapCoroutine` trait (in `crate::coroutine`) with associated `Output` and `Error`. `resume` now returns `ImapCoroutineState<Output, Error>` directly; the per-coroutine `Imap*Result` enums are gone. `ImapClientStd::run<C: ImapCoroutine>` drives any coroutine to completion. Exempt (kept as-is with their own result enum): `ImapStartTls`, `ImapIdle`, `ImapMailboxWatch`.

- Migrated `ImapCoroutine` to the generator-shape pattern: `type Yield` + `type Return` + two-variant `ImapCoroutineState<Y, R>` (`Yielded(Y)` / `Complete(R)`), mirroring `core::ops::Coroutine`. Standard coroutines pick `type Yield = ImapYield { WantsRead, WantsWrite(Vec<u8>) }` and `type Return = Result<Output, Error>`. The previously-exempt streaming coroutines now also implement the trait with per-coroutine `Yield` enums: `ImapStartTls` declares `ImapStartTlsYield { WantsRead, WantsWrite, WantsStartTls(Vec<u8>) }`, `ImapIdle` declares `ImapIdleYield { WantsRead, WantsWrite, Event(ImapIdleEvent) }`, `ImapMailboxWatch` declares `ImapMailboxWatchYield { WantsRead, WantsWrite, Event(ImapMailboxWatchEvent) }`. `ImapClientStd::run<C, T, E>` is now generic over `C: ImapCoroutine<Yield = ImapYield, Return = Result<T, E>>`; streaming coroutines and `starttls` keep dedicated per-method loops.

- Added `ImapGreetingOk { capability, pre_authenticated }` as the `ImapGreetingGet` output struct (replaces the multi-field `Ok` variant of the dropped `ImapGreetingGetResult`).

[unreleased]: https://github.com/pimalaya/io-imap/compare/root..HEAD
