# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.7.1] - 2026-10-01

### Fixed

- `rfc3501::search::ImapMessageSearch` sends `CHARSET UTF-8` only when its criteria hold non-ASCII bytes, and no charset otherwise.

  Always sending it broke Outlook, which rejects the UTF-8 charset with `NO`, for every search including ASCII ones ([pimalaya/himalaya#769](https://github.com/pimalaya/himalaya/issues/769)). US-ASCII is the default RFC 3501 requires every server to support; Gmail still gets the charset its non-ASCII criteria need. The SORT fallback inherits the fix.

## [0.7.0] - 2026-09-29

### Added

- Added `ImapClientStdConnectOptions`, whose `proxy` field tunnels the connection through a SOCKS5 or HTTP proxy.

### Changed

- **BREAKING**: `ImapClientStd::connect` takes `(url, opts)`, the TLS configuration, the SASL mechanism and the session options moving into `ImapClientStdConnectOptions`.

## [0.6.1] - 2026-09-26

### Fixed

- Fixed `rfc3501::search::ImapMessageSearch` sending no charset.

  It now always sends `CHARSET UTF-8`, as SORT and THREAD do, since Gmail rejects non-ASCII criteria without it ([#3](https://github.com/pimalaya/io-imap/issues/3)).

## [0.6.0] - 2026-08-22

### Changed

- Added `watch::ImapMailboxWatchOptions::idle_timeout`, and the same option on `client::ImapMailboxWatchStreamOptions`.

  The IDLE was re-issued every 29 seconds, around 120 round trips an hour per watched mailbox. A caller whose server keeps quiet connections open can go up to the 29 minutes of RFC 2177 §3, and `None` keeps the old value.

- Changed `watch::ImapMailboxWatch::new` to take `ImapMailboxWatchOptions`, which can select polling instead of IDLE. **Breaking.**

  A polling watch yields the new `ImapMailboxWatchYield::WantsWait`, so the driver owns the wait, an effect an I/O-free coroutine cannot perform. It answers servers that accept IDLE and then never speak.

  `client::ImapMailboxWatchStreamOptions` gained the matching `poll` interval, slept in shutdown-poll steps.

- Changed `watch::ImapMailboxWatch` to no longer require QRESYNC. **Breaking.**

  Without it, the watch EXAMINEs, seeds the same `FETCH 1:* (UID FLAGS)` baseline and re-reads the whole mailbox on every IDLE wake, diffing locally into the same UID-keyed events. The cost scales with the mailbox rather than with the change.

  `ImapMailboxWatch::new` now returns `Self`, and `ImapMailboxWatchError::QresyncUnsupported` is gone.

- Changed `client::ImapClientStd::watch_mailbox` to take `ImapMailboxWatchStreamOptions`. **Breaking.**

  Its `shutdown_poll` field is the worker's read deadline, hence the worst-case latency of `close` against a silent server. The default stays five seconds, and a desktop daemon can lower it.

### Fixed

- Fixed the mailbox watch emitting deltas after the mailbox was recreated under the same name.

  Both paths re-EXAMINE on every wake, and now end the watch with `ImapMailboxWatchError::UidValidityChanged` when UIDVALIDITY changes.

## [0.5.0] - 2026-08-15

### Added

- Added the `session::ImapSessionOpen` coroutine, covering everything from an address to an authenticated session.

  It yields transport requests (`WantsTcpConnect`, `WantsTlsConnect`, `WantsUnixConnect`, `WantsTlsUpgrade`) alongside the usual reads and writes.

  Scheme dispatch, STARTTLS ordering, PREAUTH, the SASL-IR policy and `auto_id` used to live inside `ImapClientStd::connect`. A caller on any runtime now answers the yields with its own sockets and inherits the ordering and the provider quirks.

- Added the `client::ImapClient` and `client::ImapClientAsync` traits.

  Implementors write one `run` method and inherit forty-odd commands. The five coroutines with their own yields (watch, idle, streamed `APPEND`, both streamed `FETCH`es) stay outside the traits.

  `ImapClientAsync` returns `impl Future + Send`, so default bodies survive `tokio::spawn`. `ImapClient` has no `Send` bound, so a thread-affine client such as a JNI bridge can implement it.

- Added the `session::ImapSessionOpenOptions::sasl_ir` option.

  It forces the RFC 4959 initial response on (`Some(true)`) or off (`Some(false)`), and `None` follows the `SASL-IR` capability. Coremail (126.com, 163.com) advertises `SASL-IR` yet rejects the inline form with `BAD`.

- Added the `url` cargo feature, gating `session::ImapSessionTransport::from_url`.

  The TLS features enable it, and a consumer bringing its own TLS can parse IMAP URLs without the std client.

- Added `client::ImapStream::stop_retrying`.

  It makes a transport return "not ready yet" failures instead of retrying them. The watch worker needs it, since its read timeout is a shutdown poll. The default body is empty.

### Changed

- Changed `sasl::auth_login::ImapAuthLogin` to wrap io-sasl's LOGIN mechanism. **Breaking.**

  The coroutine keeps the IMAP framing and asks the mechanism what each response carries, including whether the tagged `OK` ends the exchange. The wire bytes are unchanged.

  `ImapAuthLoginError` gained `Mechanism` and lost `UnexpectedContinuationRequest`, an extra prompt now being refused by the mechanism.

- Changed `sasl::auth_plain::ImapAuthPlain` to wrap io-sasl's PLAIN mechanism. **Breaking.**

  `ImapAuthPlainError` changed as LOGIN's did. A tagged `OK` to the command now completes the exchange only when the credentials went inline, and fails with `UnexpectedOk` otherwise.

- Changed `sasl::auth_anonymous::ImapAuthAnonymous` to wrap io-sasl's ANONYMOUS mechanism. **Breaking.**

  `ImapAuthAnonymousError` gained `Mechanism` and lost `UnexpectedContinuationRequest`.

- Changed `sasl::auth_xoauth2::ImapAuthXoauth2` to wrap io-sasl's XOAUTH2 mechanism. **Breaking.**

  The mechanism answers the error challenge with the empty response Google documents, and the JSON is still reported as `NoWithError`.

  `ImapAuthXoauth2Error` gained `Mechanism` and lost `UnexpectedStatus`. An `OK` or `BAD` answer to the acknowledgement now reports what the server actually sent.

- Changed `rfc7628::auth_oauthbearer::ImapAuthOauthbearer` to wrap io-sasl's OAUTHBEARER mechanism. **Breaking.**

  It changed as XOAUTH2 did, the error challenge being answered with the single `%x01` of RFC 7628 §3.2.3.

- Changed `rfc7677::auth_scram_sha_256::ImapAuthScramSha256` to wrap io-sasl's SCRAM-SHA-256 mechanism. **Breaking.**

  All RFC 5802 computation and verification moved to the mechanism. `ImapAuthScramSha256Error` replaced its eleven RFC 5802 variants with a single `Mechanism`.

- Changed `ImapAuthScramSha256::new` to take a single `SaslScramCreds`. **Breaking.**

  The credentials carry the client nonce, so the coroutine draws no randomness, and the channel binding, which selects `SCRAM-SHA-256-PLUS`. `ImapClientStd::connect` draws a nonce when they carry none.

- Changed the SASL vocabulary to io-sasl's `Sasl` and `SaslMechanism`. **Breaking.**

  `ImapSessionOpen`, `ImapClientStd::connect` and `rfc3501::capability::available_auth_mechanisms` use them in place of pimalaya-stream's. Credential structs gained a `Creds` suffix (`SaslPlainCreds`, `SaslLoginCreds`, ...).

  `ImapSessionOpenError` gained `UnsupportedMechanism` for mechanisms io-sasl computes but this crate does not frame, and lost `ScramSha256NotEnabled`.

- Moved `hmac`, `pbkdf2` and `sha2` to dev-dependencies.

  The SCRAM crypto now lives in io-sasl. The `scram` feature keeps `rand` and enables `io-sasl/scram`.

- Made pimalaya-stream optional, enabled by the TLS provider features.

  Only the std client uses it now, so the coroutine core is truly `no_std`, depending only on io-sasl and imap-codec.

- Moved the command methods from `ImapClientStd` to the `ImapClient` trait. **Breaking.**

  Callers add `use io_imap::client::ImapClient;`. Names and semantics are unchanged, but `impl AsRef<str>` and `impl AsRef<[u8]>` arguments became `&str` and `&[u8]`, and `status` takes a `Cow<'static, [StatusDataItemName]>`.

  `watch_mailbox`, `fetch_body_stream`, `fetch_bodies_stream` and `append_stream` stay inherent to `ImapClientStd`, each encoding a runtime-specific choice.

- Renamed `client::ImapClientStdError` to `client::ImapClientError`. **Breaking.**

  It now serves both client traits. The new `Transport` variant boxes errors from transports whose I/O is not `std::io`, such as a JNI upcall.

- Replaced the trailing `ImapClientStd::connect` parameters with `session::ImapSessionOpenOptions`. **Breaking.**

  `connect(url, tls, starttls, sasl, auto_id)` became `connect(url, tls, sasl, opts)`, and `ImapSessionOpenOptions::default()` keeps the previous behaviour. The method is now a pump over `ImapSessionOpen`.

- Bumped pimalaya-stream to 0.3. **Breaking.**

  `client::ImapStream` is now implemented for its renamed `stream::Stream`. It also arms a one-minute read deadline at connect time, so a silent server ends the exchange instead of blocking forever.

- Changed `ImapClient::greeting` to return the whole `ImapGreetingOk`. **Breaking.**

  Callers append `.capability`. It also reports `pre_authenticated`, which the old signature discarded.

- Moved `default_alpn` and `default_port` into the `session` module.

  They sit next to the scheme table, no longer require the `client` feature, and stay re-exported from `client`.

- Raised the minimum supported Rust version from 1.87 to 1.88, following pimalaya-stream.

### Fixed

- Fixed SCRAM-SHA-256 accepting a tagged `OK` in place of the server-final-message.

  The server signature was never verified, skipping mutual authentication. The mechanism now refuses it with `ServerSignatureNotVerified`.

- Fixed `EAGAIN` ending an exchange on macOS. **Behaviour change.**

  Long exchanges failed with `Resource temporarily unavailable (os error 35)`, such as a slow `AUTHENTICATE` or a `SORT` fallback `FETCH` on a large Gmail mailbox (himalaya#731, himalaya#732).

  pimalaya-stream now retries such failures for a minute, so every protocol crate inherits the fix. The watch worker opts out, its read timeout being a shutdown poll.

- Fixed the handshake and the streamed `FETCH` and `APPEND` spinning on a closed connection.

  They now fail with `UnexpectedEof`. Only `ImapClient::run` checked for an empty read.

- Fixed `ImapSessionOpen` discarding bytes trailing the `STARTTLS` response. **Behaviour change.**

  RFC 3501 §6.2.1 forbids them, as they signal injected plaintext commands. The upgrade is now refused with `ImapSessionOpenError::StartTlsInjection`.

- Fixed the build with the `client` feature alone.

  `impl ImapStream for StreamStd` was ungated while its import was gated behind the TLS features.

## [0.4.0] - 2026-08-07

### Added

- Added `rfc3501::fetch_stream_batch::ImapMessageFetchStreamBatch` and `ImapClientStd::fetch_bodies_stream`.

  They stream the bodies of a whole sequence set with one `UID FETCH <set> (UID BODY.PEEK[])`, so N bodies cost one round trip. Each body goes to its own sink via `open(uid)` and `done(uid, sink)`, never held whole in memory.

  `BODY.PEEK[]` leaves `\Seen` alone. A body without a parseable `UID` fails with `UidMissing` rather than being misrouted.

- Added `rfc3501::capability::available_auth_mechanisms`.

  It maps advertised capabilities to the `SaslMechanism`s a client can use, most preferred first and `LOGIN` last unless `LOGINDISABLED`. A setup wizard can offer only what the server supports.

- Added `rfc4315::expunge_uid::ImapMessageExpungeUid` and `ImapClientStd::uid_expunge`.

  `UID EXPUNGE` removes only the `\Deleted` messages in the given set, leaving the others untouched. It requires `UIDPLUS`.

### Changed

- Made pimalaya-stream a required dependency, pulled with no features.

  This lets `available_auth_mechanisms` live in the coroutine core. Its socket and TLS layers still require a TLS provider feature.

- Reworked `ImapRaw` into a byte-verbatim batch passthrough. **Breaking.**

  `ImapRaw::new` and `ImapClientStd::raw` take `impl AsRef<[u8]>` and send it as-is, so callers tag each command and end it with CRLF. The exchange reads until every tag is acknowledged, in any order (RFC 3501 §5.5).

  `ImapRaw::new` is now fallible, rejecting an empty, untagged, duplicate-tagged or unterminated batch via new `ImapRawError` variants.

- Added the required `ImapStream::set_read_timeout` method. **Breaking.**

  The blanket `ImapStream` impl is gone, so custom transports implement the trait by hand. `ImapClientStd::new` and `set_stream` now bound on `S: ImapStream`.

### Fixed

- Fixed commands failing after 5 seconds of server silence.

  `ImapClientStd::connect` no longer sets a per-read timeout, which broke slow SEARCH or SORT and large mailboxes. Only the watch worker keeps a periodic wakeup, treated as a shutdown check rather than an error.

## [0.3.1] - 2026-07-25

### Added

- Added `unix://` support to `ImapClientStd::connect`.

  It reaches a local socket proxy such as sirup via `StreamStd::connect_unix`.

- Added PREAUTH handling to `ImapClientStd::connect`.

  A `PREAUTH` greeting skips the SASL step, recorded in the new `ImapClientStd::pre_authenticated` field.

- Added `tag::set_tag_prefix`, setting a global tag prefix.

  It avoids tag conflicts between several io-imap instances.

- Added `default_port`.

  It returns 993 for `imaps` and 143 otherwise, so config-based callers derive the same fallback as `ImapClientStd::connect`.

### Fixed

- Fixed the std client spinning on a closed connection.

  A zero-length read now returns `UnexpectedEof`.

## [0.3.0] - 2026-07-25

### Fixed

- Fixed `ImapMessageMove` losing the `COPYUID` returned in an untagged `OK`.

  RFC 6851 §4.4 servers such as Fastmail send it before the `EXPUNGE`, not in the tagged reply. Both are now read, tagged first.

- Fixed the SORT fallback ordering `SortKey::Date` by weekday name.

  Dates are now parsed to instants, honouring the offset. Absent or unparsable dates sort first.

- Fixed `ImapMailboxWatch` opening the mailbox with SELECT.

  It now uses read-only EXAMINE, so it never mutates the mailbox nor resets `\Recent`. The `ImapMailboxWatchError` `Select*` variants became `Examine*`.

## [0.2.0] - 2026-07-15

### Added

- Added a client-side SORT fallback via `ImapMessageSortOptions::fallback`.

  With it, the coroutine SEARCHes, FETCHes the sort keys in chunks of 255 and sorts locally, returning the same result as a server SORT.

  Arrival, Date, Size and Subject are honoured. From, To, Cc and Display fall back to Date, as imap-types `Address` has no `Ord`.

- Added `ImapMessageFetchStream` and `ImapClientStd::fetch_body_stream`.

  They stream one message body (`BODY.PEEK[]`) into a caller `Write` sink instead of buffering it. A short body fails with `ImapMessageFetchStreamError::ShortBody`, and a missing id completes with an empty sink.

- Added `ImapMessageAppendStream` and `ImapClientStd::append_stream`.

  They pump the message from any `Read` source of known length straight to the socket. A short source poisons the connection and fails with `ImapMessageAppendStreamError::ShortMessage`.

- Added `ImapMessageAppendOptions::non_sync`.

  It sends a non-synchronising literal (`{N+}`, LITERAL+ or LITERAL-) without waiting for the continuation. The default `{N}` lets the server reject before the body is sent.

- Added `ImapSend::receive`.

  It parses a response whose request was written out of band, as the streamed APPEND does.

### Changed

- Bumped pimalaya-stream to 0.1.

- Changed coroutine logging to the shared Pimalaya convention.

  Coroutines emit a `debug` on state changes, usually followed by a `trace` with the data, instead of a per-resume trace.

- Changed the `ImapClientStd` methods to take their coroutine options struct.

  `id`, `select`, `examine`, `fetch`, `search`, `store`, `copy`, `move`, `thread` and `sort` take their `Imap*Options` last and forward it unchanged.

- Renamed the send primitive types to the crate naming scheme.

  `SendImapCommand`, `SendImapCommandOk`, `SendImapCommandError` and `SendImapCommandResult` became `ImapSend`, `ImapSendOutput`, `ImapSendError` and `ImapSendResult`. `ImapSendResult::Ok` now boxes its `ImapSendOutput`.

- Renamed `SelectData` and `SelectFetch` to `ImapMailboxSelectData` and `ImapMailboxSelectFetch`.

- Renamed `ImapMailboxSort*` to `ImapMessageSort*`.

  It matches `ImapMessageThread`. `ImapClientStd::sort` keeps its name, and its error variant is now `ImapClientStdError::MessageSort`.

- Changed `ImapMessageAppend::new` to take the message as `Vec<u8>`.

  `ImapClientStd::append` takes `&[u8]`. Both APPEND coroutines share `ImapMessageAppendOptions` (`flags`, `date`, `non_sync`).

## [0.1.0] - 2026-06-03

### Added

- Added the `ImapCoroutine` trait mirroring `core::ops::Coroutine`.

  It has `Yield` and `Return` types and a two-variant `ImapCoroutineState<Y, R>`. Standard coroutines yield the shared `ImapYield`, and event-emitting ones declare their own with an `Event(...)` variant.

- Added the `imap_try!` macro, the coroutine equivalent of `?`.

  It advances one inner resume step, re-yields intermediate yields and short-circuits on `Complete(Err(_))`.

- Added I/O-free IMAP IDLE coroutine following RFC 2177.

  It yields an `ImapIdleEvent` per unilateral untagged batch, and refreshes every 29 seconds by default to survive middle-boxes.

- Added I/O-free IMAP ID coroutine following RFC 2971.

  It returns the server's identification parameters, or sends `ID NIL` when none are passed.

- Added I/O-free IMAP4rev1 coroutines following RFC 3501.

  greeting, capability, login, logout, starttls, list, lsub, status, create, delete, rename, subscribe, unsubscribe, select, examine, close, check, expunge, fetch (range + single-message), search, store (echo + silent), copy, append, noop.

- Added I/O-free IMAP UNSELECT coroutine following RFC 3691.

  It closes the selected mailbox without expunging `\Deleted` messages.

- Added I/O-free IMAP APPENDUID-only coroutine following RFC 4315 (UIDPLUS).

  Lighter than `ImapMessageAppend`, it skips the EXISTS count and returns only the APPENDUID pair.

- Added I/O-free IMAP ENABLE coroutine following RFC 5161.

  It returns the server's `ENABLED` capability list.

- Added I/O-free IMAP SORT and THREAD coroutines following RFC 5256.

  Each supports the `UID` variant via its options struct.

- Added I/O-free IMAP MOVE coroutine following RFC 6851.

  It surfaces the optional `[COPYUID …]` triple when the server announces UIDPLUS.

- Added I/O-free SASL coroutines under `crate::sasl`: ANONYMOUS, LOGIN, PLAIN, XOAUTH2.

  Each supports both the non-IR and SASL-IR (RFC 4959) flows.

- Added I/O-free SASL OAUTHBEARER coroutine following RFC 7628.

  It supports both non-IR and SASL-IR flows.

- Added I/O-free SASL SCRAM-SHA-256 coroutine following RFC 7677, behind the `scram` cargo feature.

- Added the optional `auto_id` field on every auth and login coroutine.

  It chains an RFC 2971 `ID` right after the tagged auth response, as mail.qq.com and Fastmail require. An empty vec sends `ID NIL`.

- Added the `ImapMailboxWatch` composite coroutine.

  It chains ENABLE QRESYNC, SELECT (CONDSTORE), a `FETCH 1:*` baseline, IDLE and SELECT (QRESYNC) delta pulls. It emits UID-keyed `EnvelopeAdded`, `FlagsAdded`, `FlagsRemoved` and `EnvelopeRemoved` events.

- Added the `client` cargo feature enabling `ImapClientStd::new(stream)`.

  A blocking light client over any `Read + Write` stream, exposing one method per IMAP coroutine.

- Added `ImapClientStd::watch_mailbox`.

  It consumes the client and runs `ImapMailboxWatch` on a worker thread, exposing events on a bounded channel. `close()` flips a shutdown flag and joins the worker.

- Added the `rustls-ring` cargo feature (default) enabling `ImapClientStd::connect`.

  It opens `imap://` or `imaps://` via [pimalaya/stream](https://github.com/pimalaya/stream) with rustls and ring, runs STARTTLS when asked, then SASL, and returns an authenticated client.

- Added the `rustls-aws` cargo feature.

  Same full client as `rustls-ring`, with the aws-lc-rs crypto provider.

- Added the `native-tls` cargo feature.

  Same full client, backed by the platform's `native-tls` implementation.

- Added the `vendored` cargo feature.

  It compiles the TLS dependencies in vendored mode (forwarded to `pimalaya-stream/vendored`).

[unreleased]: https://github.com/pimalaya/io-imap/compare/v0.7.1..HEAD
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
