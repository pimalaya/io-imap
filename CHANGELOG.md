# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added basic I/O-free coroutines.

- Added standard, blocking client.

- Exposed `ImapClientStd::take_context` and `ImapClientStd::put_context` so external coroutines (IDLE drivers, custom orchestrators) can borrow the session context without consuming the client.

[unreleased]: https://github.com/pimalaya/io-imap/compare/root..HEAD
