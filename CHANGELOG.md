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

- Flattened `ImapIdleDone` into a plain `Arc<AtomicBool>`: `ImapIdle::new` now takes `done: Arc<AtomicBool>` directly. Callers use `done.store(true, Ordering::SeqCst)` / `done.load(Ordering::SeqCst)` instead of the wrapper's `done()` / `is_done()` methods.

[unreleased]: https://github.com/pimalaya/io-imap/compare/root..HEAD
