# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- `watch::ImapMailboxWatch` no longer requires QRESYNC. **Breaking.**

  The capability list now selects a path instead of gating the watch: with QRESYNC nothing changes, and without it the watcher opens a plain EXAMINE, seeds the same `FETCH 1:* (UID FLAGS)` baseline, and re-reads the whole mailbox on every IDLE wake, diffing it against that baseline to emit the same UID-keyed events. A server that cannot report what changed is answered by asking it everything, the way `SORT` already falls back to `SEARCH` plus a local sort. The events are identical; the cost scales with the mailbox rather than with the change.

  `ImapMailboxWatch::new` returns `Self` rather than `Result<Self, _>`, and `ImapMailboxWatchError::QresyncUnsupported` is gone, since nothing rejects a server any more.

### Fixed

- The mailbox watch now ends with the new `ImapMailboxWatchError::UidValidityChanged` when the watched mailbox is recreated under the same name, instead of emitting deltas keyed on UIDs that mean something else. Both paths re-EXAMINE before resyncing, so the check runs on every wake.

## [0.5.0] - 2026-08-15

### Added

- Added the `session` module, holding `ImapSessionOpen`: a composite coroutine covering everything between an address and an authenticated session, with transport-shaped yields (`WantsTcpConnect`, `WantsTlsConnect`, `WantsUnixConnect`, `WantsTlsUpgrade`) alongside the usual reads and writes.

  Scheme dispatch, STARTTLS ordering, the greeting, PREAUTH detection, the SASL-IR policy with its Coremail override, `auto_id` chaining and the SASL mechanism match all used to live inside `ImapClientStd::connect`, where no consumer on another runtime could reach them. A caller now answers the transport yields with its own sockets and inherits the ordering and the provider quirks; a caller that skips a step cannot advance, because the state machine never asks for the next one.

- Added the `client::ImapClient` and `client::ImapClientAsync` traits. Implement one `run` method, inherit forty-odd commands.

  The `Yield = ImapYield` bound on `run` makes the surface self-selecting: coroutines that every client wraps identically are defaulted methods, and the five that declare their own yield vocabulary (watch, idle, streamed `APPEND`, the two streamed `FETCH`es) fall outside the trait, which is where implementations are expected to diverge anyway. `ImapClientAsync` declares `-> impl Future<..> + Send` with `Send` as a supertrait, so anything built from a default body survives `tokio::spawn`; a plain `async fn` in a trait cannot express that. `ImapClient` carries no `Send` bound on purpose, since a blocking call returns a value rather than a future and the bound would exclude a thread-affine client such as a JNI bridge. Neither trait is dyn-compatible: the dynamism this crate needs lives at `client::ImapStream`.

- Added the `session::ImapSessionOpenOptions::sasl_ir` option.

  Forces the RFC 4959 SASL-IR initial response on or off for every SASL mechanism: `Some(true)` always inlines it with `AUTHENTICATE`, `Some(false)` waits for the server's continuation request, and `None` follows the advertised `SASL-IR` capability. Coremail (126.com, 163.com) advertises `SASL-IR` yet answers the inline form with a tagged `BAD`, which no capability inspection can predict.

- Added the `url` cargo feature, gating `session::ImapSessionTransport::from_url`. The three TLS features enable it. A consumer that brings its own TLS can parse IMAP URLs without pulling in the std client.

- Added `client::ImapStream::stop_retrying`, telling a transport to hand back the failures that only mean "not ready yet" instead of retrying them.

  The mailbox watch worker is what needs it: it arms a read timeout precisely to be woken up, and pimalaya-stream now retries such a wakeup away by default, which would leave the shutdown flag unchecked until the server next spoke. The method is provided and empty, so a transport that never retries inherits it and a custom one overrides it.

### Changed

- `sasl::auth_login::ImapAuthLogin` now wraps io-sasl's LOGIN mechanism instead of computing the payloads itself. **Breaking.**

  The coroutine keeps the IMAP half of the exchange, the `AUTHENTICATE LOGIN` command, the continuation requests, the tagged response and the post-auth follow-ups, and asks the mechanism what each response carries. Nothing in this crate knows any more that LOGIN answers two prompts in a fixed order, and the tagged `OK` is handed to the mechanism as the end of the exchange rather than assumed to be one, which is what will stop a SCRAM profile from treating a success reply as proof the server never gave. The wire bytes are unchanged, in both the SASL-IR and the two-prompt flows.

  `ImapAuthLoginError` gained a `Mechanism` variant carrying the mechanism's own failure, and lost `UnexpectedContinuationRequest`: a prompt arriving once LOGIN has nothing left to say is now refused by the mechanism, which is the only party that knows how many prompts it answers.

- `sasl::auth_plain::ImapAuthPlain` now wraps io-sasl's PLAIN mechanism, the same way. **Breaking.**

  The NUL-separated triple is the mechanism's, and this crate keeps the command, the challenge and the tagged response. `ImapAuthPlainError` gained `Mechanism` and lost `UnexpectedContinuationRequest`, as LOGIN did. One behaviour was tightened on the way: a tagged `OK` answering the command now completes the exchange when the credentials went inline and fails with `UnexpectedOk` when they did not, where before the SASL-IR and the non-IR flows each hard-coded one of the two answers.

- `sasl::auth_anonymous::ImapAuthAnonymous` now wraps io-sasl's ANONYMOUS mechanism. **Breaking.**

  `ImapAuthAnonymousError` gained `Mechanism` and lost `UnexpectedContinuationRequest`.

- `sasl::auth_xoauth2::ImapAuthXoauth2` and `rfc7628::auth_oauthbearer::ImapAuthOauthbearer` now wrap io-sasl's XOAUTH2 and OAUTHBEARER mechanisms. **Breaking.**

  The rejection dance is the mechanism's: a challenge carrying the error JSON is answered with the empty response Google documents, or with the single `%x01` of RFC 7628 section 3.2.3, and the JSON comes back out when the exchange is declared over, still reported as `NoWithError`. Both error types gained `Mechanism` and lost `UnexpectedStatus`: a server answering the acknowledgement with `OK` instead of `NO` now reports the rejection it sent, and one answering with `BAD` reports the `BAD` text, both of which say more than the variant they replace.

- `rfc7677::auth_scram_sha_256::ImapAuthScramSha256` now wraps io-sasl's SCRAM-SHA-256 mechanism. **Breaking.**

  RFC 5802 leaves this crate entirely: the salted password, the client proof, the parsing of the server messages and the verification of the server signature are the mechanism's. `ImapAuthScramSha256Error` keeps its framing variants and replaces the eleven RFC 5802 ones with a single `Mechanism`.

- `ImapAuthScramSha256::new` takes a single `SaslScramCreds` in place of the user and password pair, and draws no randomness. **Breaking.**

  The credentials carry the client nonce, so the coroutine is free of randomness as well as of I/O, and they carry the channel binding, which decides whether the exchange announces `SCRAM-SHA-256` or `SCRAM-SHA-256-PLUS`: a caller extracting binding material from its TLS session no longer has it dropped on the floor. `ImapClientStd::connect` draws a nonce for SCRAM credentials that carry none, an empty nonce being no nonce at all as far as RFC 5802 is concerned, so `rand` now lives in the std client rather than in the coroutine core.

  **This fixes a defect.** A server ending the exchange with a tagged `OK` in place of its server-final-message was reported as a success, with the server signature never verified, which is mutual authentication skipped by omission. The mechanism now refuses it with `ServerSignatureNotVerified`.

- Moved `hmac`, `pbkdf2` and `sha2` to dev-dependencies, the SCRAM crypto now living in io-sasl. The `scram` cargo feature keeps `rand` and enables `io-sasl/scram`.

- Took the SASL vocabulary from io-sasl: `ImapSessionOpen`, `ImapClientStd::connect` and `rfc3501::capability::available_auth_mechanisms` now speak `io_sasl::mechanism::Sasl` and `io_sasl::mechanism::SaslMechanism` rather than the pimalaya-stream ones. **Breaking.**

  The credential structs gained their `Creds` suffix (`SaslPlainCreds`, `SaslLoginCreds`, ...). io-sasl computes more mechanisms than this crate frames, so `ImapSessionOpenError` gained `UnsupportedMechanism`, naming what it was handed rather than skipping it silently; `ScramSha256NotEnabled` is gone, a build without the `scram` feature having no SCRAM credentials to be handed in the first place.

- Made pimalaya-stream an optional dependency, enabled by the TLS provider features.

  Nothing outside the std client reaches for it now that the SASL vocabulary comes from io-sasl, so the `#![no_std]` claim of the coroutine core is true: it depends on io-sasl and imap-codec, and on nothing else of ours.

- Moved the command methods off `ImapClientStd` and onto the `ImapClient` trait. **Breaking.**

  Callers add `use io_imap::client::ImapClient;`. The methods keep their names and semantics. Argument types that were `impl AsRef<str>` or `impl AsRef<[u8]>` are now `&str` and `&[u8]`, and `status` takes `Cow<'static, [StatusDataItemName]>` rather than `impl Into<..>`, so one signature serves both the blocking and the async trait. The four opinionated methods (`watch_mailbox`, `fetch_body_stream`, `fetch_bodies_stream`, `append_stream`) stay inherent to `ImapClientStd`, because each encodes a runtime-specific choice.

- Renamed `client::ImapClientStdError` to `client::ImapClientError` and gave it a `Transport` variant. **Breaking.**

  It is now the error type of both client traits rather than of one concrete client, so the name no longer says `Std`. `Transport` carries a boxed error for implementors whose I/O is not `std::io::Error`, such as a JNI upcall.

- Replaced the trailing `ImapClientStd::connect` parameters with `session::ImapSessionOpenOptions`. **Breaking.**

  `connect(url, tls, starttls, sasl, auto_id)` becomes `connect(url, tls, sasl, opts)`, where `opts` carries `starttls`, `auto_id` and the new `sasl_ir`. The method is now a pump over `ImapSessionOpen` that answers its transport yields with a pimalaya-stream `Stream`, and holds no protocol decision of its own. `ImapSessionOpenOptions::default()` reproduces the previous behaviour.

- The std client runs on pimalaya-stream 0.3, and `client::ImapStream` is implemented for its renamed `stream::Stream`. **Breaking.**

  The transport crate renamed `StreamStd` to `stream::Stream` and moved its constructors onto per-transport options structs, which is what this crate now calls. It also arms a socket read deadline of its own at connect time, one minute by default, so a server going silent on a healthy connection ends the exchange instead of blocking forever.

- `ImapClient::greeting` returns the whole `ImapGreetingOk` rather than just its capability list. **Breaking.** Callers append `.capability`. The greeting also reports `pre_authenticated`, which the old signature discarded.

- Moved `default_alpn` and `default_port` into the `session` module, next to the scheme table they belong to, and re-exported them from `client` so existing call sites keep working. They no longer require the `client` feature.

- Raised the minimum supported Rust version from 1.87 to 1.88, following pimalaya-stream.

### Fixed

- A stream reporting it is not ready no longer kills the exchange. **Behaviour change.**

  `EAGAIN` is not supposed to reach a blocking socket, yet macOS callers saw one surface mid-exchange and end the command with a bare `Resource temporarily unavailable (os error 35)`, the more readily the longer the exchange ran: on a slow `AUTHENTICATE` against a 260k-message Gmail mailbox, or midway through the chunked `FETCH` a `SORT` fallback runs (himalaya#731, himalaya#732). The fix landed in pimalaya-stream, whose `Read` and `Write` now retry such a failure for a minute before giving up, so every protocol crate inherits it rather than each carrying its own loop. This crate only says where the policy does not apply: the mailbox watch worker turns retries off, its read-timeout wakeup being a shutdown poll rather than a failure.

- A connection closed mid-response during the handshake or a streamed `FETCH` or `APPEND` now fails with `UnexpectedEof` instead of spinning. Only `ImapClient::run` checked for the empty read; the other loops resumed their coroutine with an empty slice, which asked for another read, forever.

- `ImapSessionOpen` refuses the TLS upgrade when the server appends bytes to its `STARTTLS` tagged response, instead of discarding them. **Behaviour change.**

  RFC 3501 §6.2.1 forbids trailing bytes, so their presence means an attacker injected plaintext commands the server would replay inside the TLS session. `ImapStartTls` has always returned them and documented them as an injection signal, but `ImapClientStd::connect` threw the value away. It now surfaces as `ImapSessionOpenError::StartTlsInjection`.

- Building with the `client` feature alone now works. `impl ImapStream for StreamStd` was ungated while the `StreamStd` import was gated behind the TLS features, so the light client (the case where the caller brings its own transport) failed to compile.

## [0.4.0] - 2026-08-07

### Added

- Added `rfc3501::fetch_stream_batch::ImapMessageFetchStreamBatch`, the batched `UID FETCH <set> (UID BODY.PEEK[])` body-stream coroutine, and the `ImapClientStd::fetch_bodies_stream` convenience method. It fetches the bodies of a whole sequence set in **one** command, so N bodies cost one round trip instead of N.

  Each message is routed to its own sink: `open(uid)` returns a fresh sink when a message begins, the body is streamed into it, and `done(uid, sink)` commits it when the message ends, so no body is ever held in memory whole. `BODY.PEEK[]` leaves `\Seen` alone (a sync must not mark what it reads) and the `UID` data item makes every returned body self-identifying, since a batched response arrives in server order. A UID requested but absent on the server simply never calls `open` / `done`. A body whose FETCH line carries no parseable `UID` fails with `UidMissing` rather than misrouting the body, so the caller can fall back to per-message fetches.

- Added `rfc3501::capability::available_auth_mechanisms`, mapping a server's advertised capability list to the pimalaya-stream `SaslMechanism` tags a client authenticates with, most preferred first and the plain IMAP `LOGIN` command last (offered unless `LOGINDISABLED`).

  It lets a caller (a setup wizard) offer only what the server actually supports instead of guessing a SASL mechanism; a perdition-style proxy advertising a bare `IMAP4 IMAP4REV1` yields just the `LOGIN` command. Reusing the existing `SaslMechanism` rather than a new enum keeps the probe result and the `Sasl` the client connects with in one vocabulary. It lives in the coroutine core (no `client` feature or TLS provider required), so a caller driving the coroutines over its own transport can use it too.

- Added `rfc4315::expunge_uid::ImapMessageExpungeUid`, the `UID EXPUNGE <sequence-set>` coroutine (RFC 4315, UIDPLUS), and the `ImapClientStd::uid_expunge` convenience method. Unlike plain `EXPUNGE`, it permanently removes only the `\Deleted` messages whose UID is in the given set, leaving any other `\Deleted` message untouched. Requires the server to advertise `UIDPLUS` (check `supports_uidplus`).

### Changed

- Made pimalaya-stream a non-optional dependency, pulled with no features so a minimal build gets only its SASL credential types (no TLS provider, no socket runtime).

  It was previously optional and enabled only by a TLS-provider feature. Making it always present lets `available_auth_mechanisms` live in the coroutine core and return `SaslMechanism` regardless of features. The heavier `std::stream` and `tls` layers still require a TLS-provider feature, so a no-provider build stays lean.

- Reworked `ImapRaw` into a byte-verbatim batch passthrough. **Breaking.**

  `ImapRaw::new` (and `ImapClientStd::raw`) now take `impl AsRef<[u8]>` and send the given bytes exactly as-is: no tag is injected and no CRLF is trimmed or appended. Callers therefore tag every command and separate them with CRLF, which lets a whole pipeline be sent in one exchange. The input is parsed up front to collect every command's tag, and the exchange reads until all of them are acknowledged, tolerating out-of-order tagged completions (RFC 3501 §5.5). `ImapRaw::new` is now fallible, validating the input and rejecting an untagged, duplicate-tagged, unterminated or empty batch via the new `ImapRawError` variants `NoCommand`, `MissingTag`, `DuplicateTag` and `IncompleteCommand`.

- Added a required `set_read_timeout` method to the `ImapStream` trait and made it an explicit contract. **Breaking.**

  The blanket `impl<T: Read + Write + Send + Any> ImapStream for T` is gone: `ImapStream` is now implemented for `StreamStd` directly, and a custom transport implements it (and the new `set_read_timeout`, no-op when it cannot bound a read) by hand. Accordingly `ImapClientStd::new` and `set_stream` now bound their stream on `S: ImapStream` rather than `S: Read + Write + Send`. This lets the mailbox watch worker apply its shutdown-poll wakeup through the trait instead of downcasting to the concrete stream.

### Fixed

- Removed the blanket 5-second per-read timeout from `ImapClientStd::connect`, which made any command fail spuriously when the server stayed silent for more than 5 seconds on a single read.

  The timeout was a per-read deadline, not a whole-command one, so a server that paused before answering (a slow server-side SEARCH or SORT, a large mailbox, a loaded server) or stalled mid-stream surfaced as a fatal error. The periodic wakeup that lets a background mailbox watch observe its shutdown flag now lives on the watch worker alone, and a read timeout there is treated as a wakeup that re-checks shutdown and resumes, instead of tearing the watch down on a silent IDLE.

## [0.3.1] - 2026-07-25

### Added

- Added `unix://` URL scheme support and PREAUTH handling to `ImapClientStd::connect`.

  A `unix://` URL now connects to a local Unix domain socket (via `StreamStd::connect_unix` over its path) to reach a socket proxy such as sirup. When the server greeting is `PREAUTH` the session opens already authenticated, so the SASL step is skipped; the new `ImapClientStd::pre_authenticated` field records it. Host extraction for the `imap`/`imaps` schemes moved into a `tcp_host` helper.

- Added a global tag prefix that can be set `crate::tag::set_tag_prefix`.

  This avoid tag conflicts between multiple instances of `io-imap`.

- Added `default_port`, returning the default IMAP port for a scheme (993 for `imaps`, 143 otherwise).

  Exposed so config-based callers derive the fallback port identically to `ImapClientStd::connect`, which now shares the same helper.

### Fixed

- Fixed the std client spinning on a closed connection: a zero-length read is now treated as EOF and returns an `UnexpectedEof` error instead of feeding the coroutine an empty buffer forever.

## [0.3.0] - 2026-07-25

### Fixed

- Fixed `ImapMessageMove` losing the `COPYUID` triple when the server returns it in an untagged `OK` rather than the tagged reply.

  RFC 6851 §4.4 servers (Fastmail among them) emit the MOVE `COPYUID` in an untagged `OK` before the `EXPUNGE`, not in the tagged response the coroutine inspected, so every successful move returned `None`. It now reads the code from the tagged reply or any untagged status response, tagged first.

- Fixed the client-side SORT fallback ordering `SortKey::Date` by the header's leading weekday instead of chronologically.

  The ENVELOPE date arrives as the raw RFC 5322 `Date:` header, so a lexical byte compare ordered messages by weekday name. It now parses each header to an instant, honouring the timezone offset, before comparing; an absent or unparsable date sorts first, deterministically.

- Fixed `ImapMailboxWatch` opening the mailbox with SELECT instead of EXAMINE.

  SELECT starts a read-write session and resets `\Recent` on every re-open, but the watcher only reads. It now opens the mailbox read-only with EXAMINE (QRESYNC/CONDSTORE), so it never mutates the mailbox and avoids the `\Recent` churn across its IDLE and re-open loop. The `ImapMailboxWatchError` `Select*` variants become `Examine*` accordingly.

## [0.2.0] - 2026-07-15

### Added

- Added a client-side fallback to IMAP SORT via the `fallback` flag on `ImapMessageSortOptions`.

  The flag is fed by the consumer from a SORT capability check, or by choice. With `fallback == false` the coroutine runs a plain server SORT; with `fallback == true` it SEARCHes the candidates, FETCHes the sort keys (chunked at 255), and sorts locally, returning the same `Vec<NonZeroU32>` either way. The local sort ports himalaya 1.2.0's semantics: Arrival/Date/Size/Subject are honoured; From/To/Cc/Display defer to the Date tie-break (imap-types `Address` has no `Ord`).

- Added streaming IMAP FETCH body via `ImapMessageFetchStream` and `ImapClientStd::fetch_body_stream`.

  Fetches one message body (single sequence number or UID, `BODY.PEEK[]` only) and streams it straight into a caller `Write` sink instead of buffering it whole. The body literal bypasses the `Fragmentizer`: the coroutine feeds it the framing lines one at a time, hands the announced octets to the caller via `ImapMessageFetchStreamYield::BodyChunk` / `WantsStream`, then resumes line parsing for the tagged response. A socket short of the declared length surfaces `ImapMessageFetchStreamError::ShortBody`; a missing id completes with an empty sink.

- Added streaming IMAP APPEND via `ImapMessageAppendStream` and `ImapClientStd::append_stream`.

  Separate coroutine (own `ImapMessageAppendStreamYield`) that yields `WantsStream` at the literal boundary so the caller pumps the declared message octets straight from its own source to the socket; the body never lands in memory whole. `append_stream(mailbox, source, len, opts)` takes any `Read` source plus its exact octet count (IMAP declares it up front). A short source poisons the connection and surfaces `ImapMessageAppendStreamError::ShortMessage`.

- Added the `non_sync` option on `ImapMessageAppendOptions`.

  Sends a non-synchronising literal (`{N+}`) and streams the body without waiting for the server continuation (requires LITERAL+ / LITERAL-). Defaults to a synchronising `{N}` literal so the server can still reject before the body is sent.

- Added `ImapSend::receive`.

  Receive-only constructor that parses a response whose request bytes were written out of band; reused by the streamed APPEND literal.

### Changed

- Bumped pimalaya-stream to 0.1.
- Changed coroutine logging to the shared Pimalaya convention.

  The per-resume state trace is gone; coroutines now emit a `debug` with a short phrase when their state changes, usually followed by a `trace` carrying the data.

- Reworked the `ImapClientStd` methods to forward the coroutine options struct directly instead of unpacking individual flags. `id`, `select`, `examine`, `fetch`, `search`, `store`, `copy`, `move`, `thread` and `sort` now take their respective `Imap*Options` as the last argument (e.g. `fetch(sequence_set, items, opts)`, `select(mailbox, opts)`) and pass it straight through. Each is now a one-line forward.

- Renamed the send primitive types to follow the crate naming scheme: `SendImapCommand` is now `ImapSend`, `SendImapCommandOk` is now `ImapSendOutput`, `SendImapCommandError` is now `ImapSendError` and `SendImapCommandResult` is now `ImapSendResult`. `ImapSendResult::Ok` now carries a boxed `ImapSendOutput` instead of mirroring its fields inline.

- Renamed the SELECT data types to follow the crate naming scheme: `SelectData` is now `ImapMailboxSelectData` and `SelectFetch` is now `ImapMailboxSelectFetch`.

- Renamed `ImapMailboxSort` to `ImapMessageSort` (and `ImapMailboxSortOptions`/`ImapMailboxSortError` to `ImapMessageSort*`) for consistency with the sibling `ImapMessageThread`. The `ImapClientStd::sort` method name is unchanged; the error variant is now `ImapClientStdError::MessageSort`.

- Changed the buffered `ImapMessageAppend` API.

  `ImapMessageAppend::new(mailbox, message, opts)` now takes the message as `Vec<u8>` instead of a `LiteralOrLiteral8`; it still yields the shared `ImapYield` and runs under `ImapClientStd::run`. `ImapClientStd::append(mailbox, message, opts)` takes the message as `&[u8]`. Both APPEND coroutines share `ImapMessageAppendOptions` (now carrying `flags` / `date` / `non_sync`).

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

  Lighter than `ImapMessageAppend`; skips the EXISTS count and surfaces only the `NonZeroU32` APPENDUID pair.

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

  Consumes the client, spawns a worker thread that runs `ImapMailboxWatch` over the socket, exposes events on a bounded mpsc channel. `close()` flips the shared shutdown atomic and joins the worker cleanly.

- Added the `rustls-ring` cargo feature (default) enabling `ImapClientStd::connect(url, tls, starttls, sasl, auto_id)`.

  Opens `imap://` (plain TCP) or `imaps://` (implicit TLS) via [pimalaya/stream](https://github.com/pimalaya/stream) with rustls + ring crypto provider, performs the optional STARTTLS upgrade, reads greeting and capability, runs the chosen SASL mechanism, returns an authenticated client.

- Added the `rustls-aws` cargo feature.

  Same full client as `rustls-ring` but with the aws-lc-rs crypto provider.

- Added the `native-tls` cargo feature.

  Same full client backed by the platform's `native-tls` implementation.

- Added the `vendored` cargo feature.

  Compiles the underlying TLS dependencies in vendored mode (forwarded to `pimalaya-stream/vendored`).

[unreleased]: https://github.com/pimalaya/io-imap/compare/v0.5.0..HEAD
[0.5.0]: https://github.com/pimalaya/io-imap/compare/v0.4.0..v0.5.0
[0.4.0]: https://github.com/pimalaya/io-imap/compare/v0.3.1..v0.4.0
[0.3.1]: https://github.com/pimalaya/io-imap/compare/v0.3.0..v0.3.1
[0.3.0]: https://github.com/pimalaya/io-imap/compare/v0.2.0..v0.3.0
[0.2.0]: https://github.com/pimalaya/io-imap/compare/v0.1.0..v0.2.0
[0.1.0]: https://github.com/pimalaya/io-imap/compare/root..v0.1.0
