# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Dropped `io-socket` dependency. Coroutines now expose `resume(arg: Option<&[u8]>)` and emit `WantsRead` / `WantsWrite(Vec<u8>)` / domain-specific terminals (`Ok { … }`, `WantsStartTls { … }`, `Err { … }`). `Some(&[])` signals EOF. Callers own all I/O.
- Result variant shapes follow the arity rule throughout: 0 fields → unit, 1 field → tuple, ≥2 fields → struct.
- All low-level logging is now via `trace!`; no more `info!` / `debug!` / `warn!` / `error!` in this crate.
- `ImapStartTls` now terminates with `WantsStartTls { context, remaining }` so the caller can perform the TLS handshake on the underlying socket.

[unreleased]: https://github.com/pimalaya/io-imap/compare/root..HEAD
