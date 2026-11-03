# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.0] - 2026-11-03

### Added

- Added `rfc3501::fetch_stream_batch::ImapMessageFetchStreamBatchOptions`.

  Its `max_literal_len` (100 MiB by default) and per-UID `sizes` bound the bodies a server may announce, failing with the new `LiteralTooLong` error.

- Added `client::ImapClientStd::tags`, the generator answering every `WantsTag` on the connection.
- Added `send::ImapSendOutput::tag`, the tag of the command the exchange belongs to.

### Changed

- **BREAKING**: Changed every coroutine to ask its caller for command tags through the new `coroutine::ImapYield::WantsTag`.

  Every yield type carries the variant, and a resume loop answers it with the tag bytes. A missing or invalid tag fails with `MissingTag` or `InvalidTag`.

- **BREAKING**: Changed `send::ImapSend::new` and `send::ImapSend::receive` to take the tag of the command whose completion ends the exchange.
- **BREAKING**: Changed `rfc3501::select::ImapMailboxSelectData::vanished_earlier` to inclusive UID ranges.
- **BREAKING**: Changed `rfc3501::fetch_stream_batch::ImapMessageFetchStreamBatch::new` to take `(sequence_set, opts)`, the `uid` flag moving into its options.

### Fixed

- Fixed bare builds pulling std through imap-codec's `tag_generator` feature, now enabled by `client` only ([pimalaya/io-imap#4](https://github.com/pimalaya/io-imap/issues/4)).
- Fixed the build against abnf-core 0.6.1.

  imap-codec 2.0.0-alpha.9 relied on nom features abnf-core no longer enables. io-imap now requires imap-codec 2.0.0-alpha.10, which requests them itself.

- Fixed FETCH responses with a `NIL` body parameter value being dropped as undecodable ([pimalaya/himalaya#649](https://github.com/pimalaya/himalaya/issues/649)).

  Mail.ru sends `("boundary" NIL)`, which imap-codec 2.0.0-alpha.10 reads as an empty string.

- Fixed a tagged completion of another command ending an exchange and lending it its status: it is now skipped.
- Fixed SELECT and EXAMINE expanding a `VANISHED (EARLIER)` set into one entry per UID.

  A server announcing `1:4294967295` made the client allocate about 16 GiB. The set is now kept as ranges.

- Fixed `rfc3501::greeting::ImapGreetingGet` panicking on a greeting carrying a literal.

  Anyone on the path of a plaintext connection could send one. It now fails with `DecodingFailure`.

- Fixed the FETCH body streams and `rfc3501::starttls::ImapStartTls` buffering an endless response line.

  Lines are scanned incrementally and capped (1 MiB, 64 KiB before STARTTLS), failing with the new `LineTooLong` errors.

- Fixed LOGIN, AUTHENTICATE and raw commands logging credentials at trace level.

  Authentication commands now log only their name, raw batches only their command count.

- Fixed `rfc3501::copy::ImapMessageCopy` and `rfc6851::r#move::ImapMessageMove` dropping a COPYUID whose UIDVALIDITY is `0` ([pimalaya/himalaya#781](https://github.com/pimalaya/himalaya/issues/781)).

  Mailo sends `OK [COPYUID 0 1582 22704]`, which RFC 4315 forbids. Its UID sets are now read, the UIDVALIDITY returned as `0`.

- Fixed `client::ImapClientAsync::login` failing to compile on rustc 1.88 to 1.91 (E0308).

  Its default body now boxes the future instead of awaiting in an async block.

### Removed

- Removed the docs/ folder, replaced by cairn/.

## [0.7.1] - 2026-10-01

### Fixed

- Fixed `rfc3501::search::ImapMessageSearch` sending `CHARSET UTF-8` with ASCII criteria ([pimalaya/himalaya#769](https://github.com/pimalaya/himalaya/issues/769)).

  Outlook rejects that charset with `NO`, failing every search. It is now sent only for non-ASCII criteria, and the SORT fallback inherits the fix.

## [0.7.0] - 2026-09-29

### Added

- Added `ImapClientStdConnectOptions`, whose `proxy` field tunnels the connection through a SOCKS5 or HTTP proxy.

### Changed

- **BREAKING**: Changed `ImapClientStd::connect` to take `(url, opts)`.

  The TLS configuration, the SASL mechanism and the session options moved into `ImapClientStdConnectOptions`.

## [0.6.1] - 2026-09-26

### Fixed

- Fixed `rfc3501::search::ImapMessageSearch` sending no charset ([pimalaya/io-imap#3](https://github.com/pimalaya/io-imap/issues/3)).

  It now always sends `CHARSET UTF-8`, as SORT and THREAD do, since Gmail rejects non-ASCII criteria without it.

## [0.6.0] - 2026-08-22

### Added

- Added `watch::ImapMailboxWatchOptions::idle_timeout`, also on `client::ImapMailboxWatchStreamOptions`.

  A caller whose server keeps quiet connections open can re-issue IDLE up to every 29 minutes (RFC 2177 §3) instead of every 29 seconds, which `None` keeps.

### Changed

- **BREAKING**: Changed `watch::ImapMailboxWatch::new` to take `ImapMailboxWatchOptions`, which can select polling instead of IDLE.

  A polling watch yields the new `ImapMailboxWatchYield::WantsWait`, so the caller owns the wait. `client::ImapMailboxWatchStreamOptions` gained the matching `poll` interval.

- **BREAKING**: Changed `watch::ImapMailboxWatch` to no longer require QRESYNC.

  Without it, the watch re-reads the whole mailbox on every wake and diffs locally into the same events. `new` now returns `Self`, and `ImapMailboxWatchError::QresyncUnsupported` is gone.

- **BREAKING**: Changed `client::ImapClientStd::watch_mailbox` to take `ImapMailboxWatchStreamOptions`.

  Its `shutdown_poll` field (five seconds by default) is the worst-case latency of `close` against a silent server.

### Fixed

- Fixed the mailbox watch emitting deltas after the mailbox was recreated under the same name.

  It now ends with `ImapMailboxWatchError::UidValidityChanged` when UIDVALIDITY changes.

## [0.5.0] - 2026-08-15

### Added

- Added the `session::ImapSessionOpen` coroutine, covering everything from an address to an authenticated session.

  It yields transport requests (`WantsTcpConnect`, `WantsTlsConnect`, `WantsUnixConnect`, `WantsTlsUpgrade`) that a caller on any runtime answers with its own sockets.

- Added the `client::ImapClient` and `client::ImapClientAsync` traits.

  Implementors write one `run` method and inherit forty-odd commands. `ImapClientAsync` returns `impl Future + Send`, while `ImapClient` has no `Send` bound, for thread-affine clients such as a JNI bridge.

- Added `session::ImapSessionOpenOptions::sasl_ir`.

  It forces the RFC 4959 initial response on or off for servers such as Coremail, which advertise `SASL-IR` yet reject it. `None` follows the capability.

- Added the `url` cargo feature, gating `session::ImapSessionTransport::from_url`.

  The TLS features enable it, and a consumer bringing its own TLS can parse IMAP URLs without the std client.

- Added `client::ImapStream::stop_retrying`, making a transport return "not ready" failures instead of retrying them.

### Changed

- **BREAKING**: Changed `sasl::auth_login::ImapAuthLogin` to wrap io-sasl's LOGIN mechanism.

  The wire bytes are unchanged. `ImapAuthLoginError` gained `Mechanism` and lost `UnexpectedContinuationRequest`.

- **BREAKING**: Changed `sasl::auth_plain::ImapAuthPlain` to wrap io-sasl's PLAIN mechanism.

  Its error changed as LOGIN's did. A tagged `OK` now completes the exchange only when the credentials went inline, and fails with `UnexpectedOk` otherwise.

- **BREAKING**: Changed `sasl::auth_anonymous::ImapAuthAnonymous` to wrap io-sasl's ANONYMOUS mechanism.

  `ImapAuthAnonymousError` gained `Mechanism` and lost `UnexpectedContinuationRequest`.

- **BREAKING**: Changed `sasl::auth_xoauth2::ImapAuthXoauth2` to wrap io-sasl's XOAUTH2 mechanism.

  `ImapAuthXoauth2Error` gained `Mechanism` and lost `UnexpectedStatus`. The error JSON is still reported as `NoWithError`.

- **BREAKING**: Changed `rfc7628::auth_oauthbearer::ImapAuthOauthbearer` to wrap io-sasl's OAUTHBEARER mechanism.

  It changed as XOAUTH2 did, answering the error challenge with the `%x01` of RFC 7628 §3.2.3.

- **BREAKING**: Changed `rfc7677::auth_scram_sha_256::ImapAuthScramSha256` to wrap io-sasl's SCRAM-SHA-256 mechanism.

  `ImapAuthScramSha256Error` replaced its eleven RFC 5802 variants with a single `Mechanism`.

- **BREAKING**: Changed `ImapAuthScramSha256::new` to take a single `SaslScramCreds`.

  The credentials carry the client nonce, so the coroutine draws no randomness, and the channel binding selecting `SCRAM-SHA-256-PLUS`.

- **BREAKING**: Changed the SASL vocabulary to io-sasl's `Sasl` and `SaslMechanism`.

  Credential structs gained a `Creds` suffix (`SaslPlainCreds`, `SaslLoginCreds`, ...). `ImapSessionOpenError` gained `UnsupportedMechanism` and lost `ScramSha256NotEnabled`.

- **BREAKING**: Moved the command methods from `ImapClientStd` to the `ImapClient` trait.

  Callers add `use io_imap::client::ImapClient;`. `impl AsRef` arguments became `&str` and `&[u8]`, and `status` takes a `Cow<'static, [StatusDataItemName]>`.

- **BREAKING**: Renamed `client::ImapClientStdError` to `client::ImapClientError`.

  It serves both client traits, and its new `Transport` variant boxes errors from transports whose I/O is not `std::io`.

- **BREAKING**: Replaced the trailing `ImapClientStd::connect` parameters with `session::ImapSessionOpenOptions`.

  `connect(url, tls, starttls, sasl, auto_id)` became `connect(url, tls, sasl, opts)`.

- **BREAKING**: Bumped pimalaya-stream to 0.3.

  `client::ImapStream` is now implemented for its renamed `stream::Stream`, which arms a one-minute read deadline at connect time.

- **BREAKING**: Changed `ImapClient::greeting` to return the whole `ImapGreetingOk`.

  Callers append `.capability`, and it also reports `pre_authenticated`.

- Moved `hmac`, `pbkdf2` and `sha2` to dev-dependencies, the SCRAM crypto now living in io-sasl.
- Made pimalaya-stream optional, enabled by the TLS provider features, so only the std client depends on it.
- Moved `default_alpn` and `default_port` into the `session` module, still re-exported from `client`.
- Raised the minimum supported Rust version from 1.87 to 1.88, following pimalaya-stream.

### Fixed

- Fixed SCRAM-SHA-256 accepting a tagged `OK` in place of the server-final-message.

  The server signature was never verified. The mechanism now refuses it with `ServerSignatureNotVerified`.

- Fixed `EAGAIN` ending an exchange on macOS ([pimalaya/himalaya#731](https://github.com/pimalaya/himalaya/issues/731), [pimalaya/himalaya#732](https://github.com/pimalaya/himalaya/issues/732)).

  pimalaya-stream now retries such failures for a minute. The watch worker opts out, its read timeout being a shutdown poll.

- Fixed the handshake and the streamed FETCH and APPEND spinning on a closed connection: they now fail with `UnexpectedEof`.
- Fixed `ImapSessionOpen` discarding bytes trailing the STARTTLS response.

  RFC 3501 §6.2.1 forbids them, as they signal injected plaintext. The upgrade now fails with `ImapSessionOpenError::StartTlsInjection`.

- Fixed the build with the `client` feature alone.

## [0.4.0] - 2026-08-07

### Added

- Added `rfc3501::fetch_stream_batch::ImapMessageFetchStreamBatch` and `ImapClientStd::fetch_bodies_stream`.

  They stream the bodies of a whole sequence set with one `UID FETCH <set> (UID BODY.PEEK[])`, each body to its own sink. A body without a parseable `UID` fails with `UidMissing`.

- Added `rfc3501::capability::available_auth_mechanisms`.

  It maps advertised capabilities to the usable `SaslMechanism`s, most preferred first and `LOGIN` last unless `LOGINDISABLED`.

- Added `rfc4315::expunge_uid::ImapMessageExpungeUid` and `ImapClientStd::uid_expunge`.

  `UID EXPUNGE` removes only the `\Deleted` messages in the given set. It requires UIDPLUS.

### Changed

- **BREAKING**: Changed `ImapRaw` into a byte-verbatim batch passthrough.

  `ImapRaw::new` and `ImapClientStd::raw` send their bytes as-is, so callers tag and terminate each command. `ImapRaw::new` is now fallible.

- **BREAKING**: Changed `ImapStream` to require `set_read_timeout`.

  The blanket `ImapStream` impl is gone, so custom transports implement the trait by hand.

- Made pimalaya-stream a required dependency, pulled with no features.

### Fixed

- Fixed commands failing after 5 seconds of server silence.

  `ImapClientStd::connect` no longer sets a per-read timeout, which broke slow SEARCH, SORT and large mailboxes.

## [0.3.1] - 2026-07-25

### Added

- Added `unix://` support to `ImapClientStd::connect`, reaching a local socket proxy such as sirup.
- Added PREAUTH handling to `ImapClientStd::connect`.

  A `PREAUTH` greeting skips the SASL step, recorded in the new `ImapClientStd::pre_authenticated` field.

- Added `tag::set_tag_prefix`, setting a global tag prefix to avoid conflicts between io-imap instances.
- Added `default_port`, returning 993 for `imaps` and 143 otherwise.

### Fixed

- Fixed the std client spinning on a closed connection: a zero-length read now returns `UnexpectedEof`.

## [0.3.0] - 2026-07-25

### Fixed

- Fixed `ImapMessageMove` losing the COPYUID returned in an untagged `OK`.

  RFC 6851 §4.4 servers such as Fastmail send it before the EXPUNGE. Both places are now read, tagged first.

- Fixed the SORT fallback ordering `SortKey::Date` by weekday name.

  Dates are now parsed to instants, honouring the offset. Absent or unparsable dates sort first.

- Fixed `ImapMailboxWatch` opening the mailbox with SELECT.

  It now uses read-only EXAMINE, never resetting `\Recent`. The `ImapMailboxWatchError` `Select*` variants became `Examine*`.

## [0.2.0] - 2026-07-15

### Added

- Added a client-side SORT fallback via `ImapMessageSortOptions::fallback`.

  The coroutine SEARCHes, FETCHes the sort keys in chunks of 255 and sorts locally. From, To, Cc and Display fall back to Date.

- Added `ImapMessageFetchStream` and `ImapClientStd::fetch_body_stream`.

  They stream one message body into a caller `Write` sink. A short body fails with `ShortBody`, and a missing id completes with an empty sink.

- Added `ImapMessageAppendStream` and `ImapClientStd::append_stream`.

  They pump the message from any `Read` source of known length to the socket. A short source fails with `ShortMessage`.

- Added `ImapMessageAppendOptions::non_sync`, sending a non-synchronising literal (`{N+}`) without waiting for the continuation.
- Added `ImapSend::receive`, parsing a response whose request was written out of band.

### Changed

- Bumped pimalaya-stream to 0.1.
- Changed coroutine logging to the shared Pimalaya convention: a `debug` on state changes, usually followed by a `trace` with the data.
- Changed the `ImapClientStd` methods to take their coroutine options struct last.
- Renamed `SendImapCommand`, `SendImapCommandOk`, `SendImapCommandError` and `SendImapCommandResult` to `ImapSend`, `ImapSendOutput`, `ImapSendError` and `ImapSendResult`.

  `ImapSendResult::Ok` now boxes its `ImapSendOutput`.

- Renamed `SelectData` and `SelectFetch` to `ImapMailboxSelectData` and `ImapMailboxSelectFetch`.
- Renamed `ImapMailboxSort*` to `ImapMessageSort*`, matching `ImapMessageThread`.
- Changed `ImapMessageAppend::new` to take the message as `Vec<u8>`.

  `ImapClientStd::append` takes `&[u8]`, and both APPEND coroutines share `ImapMessageAppendOptions`.

## [0.1.0] - 2026-06-03

### Added

- Added the `ImapCoroutine` trait mirroring `core::ops::Coroutine`, with its `ImapCoroutineState` and the shared `ImapYield`.
- Added the `imap_try!` macro, the coroutine equivalent of `?`.
- Added the I/O-free IDLE coroutine (RFC 2177).

  It yields an `ImapIdleEvent` per unilateral untagged batch, and refreshes every 29 seconds by default.

- Added the I/O-free ID coroutine (RFC 2971).
- Added the I/O-free IMAP4rev1 coroutines (RFC 3501).

  They cover greeting, capability, login, logout, STARTTLS, list, lsub, status, create, delete, rename, subscribe, unsubscribe, select, examine, close, check, expunge, fetch, search, store, copy, append and noop.

- Added the I/O-free UNSELECT coroutine (RFC 3691).
- Added the I/O-free APPENDUID coroutine (RFC 4315), returning only the APPENDUID pair.
- Added the I/O-free ENABLE coroutine (RFC 5161).
- Added the I/O-free SORT and THREAD coroutines (RFC 5256).
- Added the I/O-free MOVE coroutine (RFC 6851), surfacing the optional COPYUID.
- Added the I/O-free ANONYMOUS, LOGIN, PLAIN and XOAUTH2 SASL coroutines, each with non-IR and SASL-IR (RFC 4959) flows.
- Added the I/O-free OAUTHBEARER SASL coroutine (RFC 7628).
- Added the I/O-free SCRAM-SHA-256 SASL coroutine (RFC 7677), behind the `scram` cargo feature.
- Added the optional `auto_id` field on every auth and login coroutine.

  It chains an RFC 2971 ID right after authentication, as mail.qq.com and Fastmail require.

- Added the `ImapMailboxWatch` composite coroutine.

  It chains ENABLE QRESYNC, SELECT (CONDSTORE), a baseline FETCH, IDLE and QRESYNC delta pulls into UID-keyed events.

- Added the `client` cargo feature and `ImapClientStd::new`, a blocking client over any `Read + Write` stream.
- Added `ImapClientStd::watch_mailbox`, running `ImapMailboxWatch` on a worker thread behind a bounded channel.
- Added the `rustls-ring` cargo feature (default), enabling `ImapClientStd::connect` with rustls and ring.
- Added the `rustls-aws` cargo feature, the same full client with the aws-lc-rs crypto provider.
- Added the `native-tls` cargo feature, the same full client with the platform TLS.
- Added the `vendored` cargo feature, compiling the TLS dependencies in vendored mode.

[unreleased]: https://github.com/pimalaya/io-imap/compare/v0.8.0..HEAD
[0.8.0]: https://github.com/pimalaya/io-imap/compare/v0.7.1..v0.8.0
[0.7.1]: https://github.com/pimalaya/io-imap/compare/v0.7.0..v0.7.1
[0.7.0]: https://github.com/pimalaya/io-imap/compare/v0.6.1..v0.7.0
[0.6.1]: https://github.com/pimalaya/io-imap/compare/v0.6.0..v0.6.1
[0.6.0]: https://github.com/pimalaya/io-imap/compare/v0.5.0..v0.6.0
[0.5.0]: https://github.com/pimalaya/io-imap/compare/v0.4.0..v0.5.0
[0.4.0]: https://github.com/pimalaya/io-imap/compare/v0.3.1..v0.4.0
[0.3.1]: https://github.com/pimalaya/io-imap/compare/v0.3.0..v0.3.1
[0.3.0]: https://github.com/pimalaya/io-imap/compare/v0.2.0..v0.3.0
[0.2.0]: https://github.com/pimalaya/io-imap/compare/v0.1.0..v0.2.0
[0.1.0]: https://github.com/pimalaya/io-imap/compare/root..v0.1.0
