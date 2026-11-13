# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **BREAKING**: Changed the pimalaya-stream dependency to 0.4.

  Its `tls::Tls` moved the trusted certificate from `cert` to `server`, and gained `client`, the certificate presented when the server asks for one (mutual TLS).

## [0.9.0] - 2026-11-13

### Added

- Added `send::ImapSendBudget`, the bounds on the untagged responses one exchange collects, set through `send::ImapSend::budget`.

  16,777,216 responses and 1 GiB by default; `ImapSendBudget::PRE_AUTH` (1024 responses, 1 MiB) for CAPABILITY, ID, LOGIN and AUTHENTICATE.

- Added `rfc3501::raw::ImapRaw::max_response_len`, 1 GiB by default.

- Added `rfc3501::fetch_stream::ImapMessageFetchStreamOptions`.

  Its `max_literal_len` (100 MiB by default) and `size` bound the body a server may announce.

- Added `watch::ImapMailboxWatchState`, handed out by `watch::ImapMailboxWatch::state` and taken back through `watch::ImapMailboxWatchOptions::resume_from`.

  A watch that lost its connection is resumed on a new one and emits what changed meanwhile, instead of taking a silent new baseline.

- Added `client::ImapMailboxWatchStream::into_state` and `client::ImapMailboxWatchStreamOptions::resume_from`, the same for the blocking watch.

- Added `send::ImapStatusError`, the kind, response code and text of a NO or BAD completion, and `client::ImapClientError::status` to read it.

- Added `client::ImapClientError::is_connection_lost`.

  True when the stream failed or ended, or the server closed the session with a BYE.

- Added `send::ImapSendOutput::skipped`, the untagged responses skipped for not decoding.

- Added `send::ImapSendOutput::alerts`, the texts of the `ALERT` response codes of an exchange.

- Added `send::ImapOutput`, the result of a command with the alerts and the skipped responses of its response.

- Added `read_only` and `no_mod_seq` to `rfc3501::select::ImapMailboxSelectData`.

- Added `rfc3501::updates::ImapMailboxUpdates`, the unsolicited EXISTS, RECENT, EXPUNGE, VANISHED and FETCH data of a response.

- Added the `No`, `Bad` and `Bye` variants to `rfc3501::starttls::ImapStartTlsError`.

- Added the `EmptyNonce` variant to `rfc7677::auth_scram_sha_256::ImapAuthScramSha256Error`.

- Added `scram` to `rfc7677::auth_scram_sha_256::ImapAuthScramSha256Options` and `session::ImapSessionOpenOptions`, the `SaslScramOptions` of io-sasl.

  Its `min_iterations` (4096 by default) and `max_iterations` (five million by default) bound the iteration count a SCRAM server may announce. `client::ImapClientStd::connect` takes it through its session options.

### Changed

- Added a dependency on [mime-rs](https://crates.io/crates/mime-rs) 0.1 for decoding RFC 2047 subjects.

- **BREAKING**: Changed the io-sasl dependency to 0.2.

  Its error enums, carried by the `Mechanism` variant of the AUTHENTICATE errors, gained variants.

- **BREAKING**: Changed AUTHENTICATE PLAIN and SCRAM-SHA-256 to prepare their credentials with SASLprep, which io-sasl 0.1 did under a feature this crate left off.

  A password that SASLprep alters is sent, or derived from, in its prepared form. A credential holding a prohibited code point fails with the `Preparation` error of the mechanism.

- **BREAKING**: Changed the `No` and `Bad` variants of every command error but `rfc3501::starttls::ImapStartTlsError` to carry a `send::ImapStatusError` instead of the text.

  The response code reaches the caller. The error messages are unchanged.

- **BREAKING**: Changed FETCH, STORE, SEARCH, SORT, THREAD, STATUS, LIST, LSUB, EXPUNGE, UID EXPUNGE, SELECT and EXAMINE to return their result in a `send::ImapOutput`, the coroutines and the client methods alike.

  The result moves to its `data` field. `rfc3501::fetch::ImapMessageFetchFirst` and `rfc3501::store::ImapMessageStoreSilent` are unchanged.

- **BREAKING**: Changed `rfc3501::noop::ImapNoop` and `rfc3501::check::ImapMailboxCheck` to return a `send::ImapOutput` of `rfc3501::updates::ImapMailboxUpdates` instead of `()`.

- **BREAKING**: Changed `watch::ImapMailboxWatchOptions` and `client::ImapMailboxWatchStreamOptions` to no longer be `Copy`, as they carry the state to resume from.

- **BREAKING**: Changed `send::ImapSend` to yield each literal as a write of its own, uncopied.

  A buffered APPEND writes its command line, its message, then the line end, in three writes. Its peak drops from three more copies of the message to one.

- **BREAKING**: Changed `send::ImapSendOutput` and `send::ImapSendResult` to no longer be generic over the encoder.

- **BREAKING**: Changed `send::ImapSend::receive` to take the tag alone.

- **BREAKING**: Changed the `DecodingFailure`, `MessageIsPoisoned` and `MessageTooLong` variants of `send::ImapSendError`, `rfc3501::greeting::ImapGreetingGetError` and `rfc2177::idle::ImapIdleError` to carry the first 1024 octets of the response instead of all of it.

- **BREAKING**: Changed `rfc7677::auth_scram_sha_256::ImapAuthScramSha256::new` to return a `Result`, refusing an empty client nonce.

- **BREAKING**: Changed the `UrlMissingHost` and `UrlUnsupportedScheme` variants of `session::ImapSessionOpenError` to hold and print the scheme, host and port of the URL instead of the whole URL.

- Changed the `scram` feature to no longer enable the rand dependency, which the three TLS features enable instead, without its default features.

  A build with `scram` alone has no dependency on std again.

- Changed `rfc3501::append::ImapMessageAppend` and `rfc4315::appenduid::ImapAppendUid` to trace the name of their command instead of the whole message.

- **BREAKING**: Changed `rfc3501::copy::ImapCopyUid` to a struct keeping the two COPYUID sets as inclusive UID ranges, in the order of the code.

  `pairs` iterates over the `(source, destination)` UIDs and `count` gives their number. COPY and MOVE return `Option<ImapCopyUid>`.

- **BREAKING**: Changed `rfc3501::fetch_stream::ImapMessageFetchStream::new` to take `(id, opts)`, the `uid` flag moving into its options.

### Fixed

- Fixed COPY and MOVE sorting the two COPYUID sets independently, which lost the pairing of source and destination UIDs.

- Fixed a tagged completion whose text holds 8-bit bytes (Dovecot echoing a UTF-8 mailbox name in a `NO`) failing the whole exchange as a decoding error: it is decoded again with those bytes read as `?`, and skipped when it belongs to another command.

- Fixed `rfc3501::fetch_stream::ImapMessageFetchStream` and `rfc3501::fetch_stream_batch::ImapMessageFetchStreamBatch` ending on the tagged completion of another command, which read as a missing message.

  They end on their own completion, and read it when its text holds 8-bit bytes.

- Fixed the two FETCH body streams dropping the bytes read past their completion: they go back to the fragmentizer.

- Fixed `rfc3501::logout::ImapLogout` failing when the BYE and the tagged completion arrive in two reads.

- Fixed `rfc3501::fetch::ImapMessageFetchFirst` returning the data of another message when the server adds its FETCH to the response.

- Fixed the client-side SORT fallback returning a message the search did not match when the server adds its FETCH to the response.

- Fixed `client::ImapClientStd` never flushing its stream after a write.

- Fixed the six AUTHENTICATE coroutines leaving their exchange open when the mechanism refuses a challenge: they send the `*` cancellation and read its reply before failing with the mechanism error.

- Fixed `rfc7677::auth_scram_sha_256::ImapAuthScramSha256` announcing `SCRAM-SHA-256` for credentials carrying a channel binding: they run under `SCRAM-SHA-256-PLUS`.

- Fixed `rfc3501::starttls::ImapStartTls` completing with success on a tagged `NO` or `BAD`, and reading past a `BYE` greeting.

- Fixed `rfc2177::idle::ImapIdle` dropping the bytes it is resumed with once `done` is set or its refresh timer has run out: the notification they held was lost.

- Fixed `rfc2177::idle::ImapIdle` dropping the data read between `DONE` and its completion: it is yielded as an event, so a watch whose IDLE is refreshed while a message arrives resyncs.

- Fixed `rfc2177::idle::ImapIdle` reporting a BYE as an empty event then an EOF: it fails with `ImapIdleError::Bye`.

- Fixed `rfc2177::idle::ImapIdle` failing on an untagged response that does not decode: it is skipped, as a command skips it.

- Fixed `watch::ImapMailboxWatch` ending its IDLE and re-reading the mailbox on any server line, a keepalive included: it wakes on EXISTS, EXPUNGE, FETCH and VANISHED only.

- Fixed `watch::ImapMailboxWatch` fetching its baseline by sequence number, which a strict server refuses on an empty mailbox: it sends `UID FETCH 1:* (UID FLAGS)`.

- Fixed `client::ImapMailboxWatchStream` hanging on close or drop when its events are not drained.

- Fixed `watch::ImapMailboxWatch` reporting a message as removed when its line was skipped for not decoding: a whole-mailbox re-read that skipped a line removes nothing, and a QRESYNC reply that skipped one keeps its resync point.

- Fixed `rfc3501::list::ImapMailboxList` and `rfc3501::lsub::ImapMailboxLsub` sending the pattern unencoded: it now goes out in modified UTF-7, the wildcards kept, as a quoted string, which iCloud requires for LSUB.

- Fixed the client-side SORT fallback of `rfc5256::sort::ImapMessageSort` to follow RFC 5256: `FROM`, `TO` and `CC` sort by the first address's mailbox instead of being ignored, `SUBJECT` by the base subject (encoded words decoded, reply and forward prefixes stripped, case ignored) instead of the raw bytes, `DATE` falls back to the internal date, and ties keep the sequence order, `REVERSE` included.

### Security

- Fixed `send::ImapSend` writing a synchronising literal before the server's continuation request.

  The literal goes out only once a `+` line is decoded, so a command refused before its literal (an APPEND over quota) no longer sends it to a server reading command lines.

- Fixed an exchange collecting untagged responses without bound while waiting for its completion.

  Past its budget `send::ImapSend` fails with the new `ResponseTooLong` error, as does `rfc3501::raw::ImapRaw` past `max_response_len`.

- Fixed COPY and MOVE expanding a COPYUID set into one entry per UID.

  A server announcing `1:4294967295` made the client allocate about 16 GiB per set. The sets are kept as ranges, and a COPYUID whose sets differ in length is dropped.

- Fixed `rfc3501::fetch_stream::ImapMessageFetchStream` streaming a body of any announced length: past its bound it fails with the new `LiteralTooLong` error.

- Fixed `rfc3501::fetch_stream_batch::ImapMessageFetchStreamBatch` streaming the body of one UID any number of times: a repeat fails with the new `UidRepeated` error.

- Fixed `client::ImapClientStd::append_stream` announcing a length over 4 GiB truncated to 32 bits while streaming all of it: it fails with the new `client::ImapClientError::MessageTooLong` before writing.

- Fixed the client-side SORT fallback taking quadratic time on a subject made of bracketed blobs.

- Fixed `client::ImapClientStd::set_stream` keeping the bytes buffered from the previous stream, which were parsed in front of what the new one delivers: the fragmentizer is emptied, its size limit kept.

- Fixed the `Debug` of `coroutine::ImapYield` and `session::ImapSessionOpenYield` printing the bytes of a write, credentials included: it prints their length.

- Fixed the URL errors of `session::ImapSessionTransport::from_url` printing the whole URL, userinfo included.

- Fixed `rfc7677::auth_scram_sha_256::ImapAuthScramSha256` accepting an empty client nonce, which any server nonce extends.

- Fixed `rfc7677::auth_scram_sha_256::ImapAuthScramSha256` accepting a client nonce shorter than 18 bytes, or holding a comma or a byte outside printable ASCII.

  Its first resume fails with the `InvalidNonce` error of the mechanism, before anything is written.

- Fixed `rfc7677::auth_scram_sha_256::ImapAuthScramSha256` deriving its key for whatever iteration count the server announced.

  A count outside the bounds of the `scram` options cancels the exchange and fails with the `IterationCountTooLow` or `IterationCountTooHigh` error of the mechanism, before the derivation runs.

### Removed

- **BREAKING**: Removed `rfc3501::logout::ImapLogoutError::MissingTagged`: a LOGOUT whose BYE is followed by the end of the stream succeeds.

- **BREAKING**: Removed `send::ImapSendOutput::message`, the echo of the command sent.

## [0.8.1] - 2026-11-03

### Changed

- Changed the minimum Rust version to 1.89.

- Replaced the base64 crate with [base64-codec](https://crates.io/crates/base64-codec) for the modified UTF-7 mailbox names.

  imap-codec still depends on the base64 crate.

- Changed the io-sasl requirement to 0.1.1, which replaced the base64 crate with base64-codec.

### Security

- Raised the pimalaya-stream requirement to 0.3.1, fixing RUSTSEC-2026-0346 to RUSTSEC-2026-0349.

  It requires rustls 0.23.46.

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

[unreleased]: https://github.com/pimalaya/io-imap/compare/v0.9.0..HEAD
[0.9.0]: https://github.com/pimalaya/io-imap/compare/v0.8.1..v0.9.0
[0.8.1]: https://github.com/pimalaya/io-imap/compare/v0.8.0..v0.8.1
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
