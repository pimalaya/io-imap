#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! # io-imap
//!
//! I/O-free IMAP client coroutines built on
//! [imap-codec](https://docs.rs/imap-codec): every command exchange is
//! a resumable state machine emitting read and write requests instead
//! of performing I/O itself, so the caller owns the socket and pumps
//! the coroutine (see the `client` feature for a ready-made
//! std-blocking pump). imap-codec is re-exported as [`codec`], with
//! imap-types as [`types`], so consumers encode and decode with the
//! exact same codec version.
//!
//! The crate ships the three standard Pimalaya layers: the I/O-free
//! coroutines (no_std core, always present), a light std client
//! (`client` feature) wrapping a caller-provided stream, and a full
//! std client (`rustls-ring` default, `rustls-aws`, `native-tls`) that
//! also opens TCP, negotiates TLS and authenticates.
//!
//! ## Layout: one module per RFC
//!
//! Like io-http and io-oauth, the source tree mirrors the specs:
//! [`rfc3501`] (IMAP4rev1 commands), [`rfc2177`] (IDLE), [`rfc2971`]
//! (ID), [`rfc3691`] (UNSELECT), [`rfc4315`] (UIDPLUS), [`rfc5161`]
//! (ENABLE), [`rfc5256`] (SORT and THREAD), [`rfc6851`] (MOVE),
//! [`rfc7628`] (OAUTHBEARER) and `rfc7677` (SCRAM-SHA-256, behind the
//! `scram` feature); the [`sasl`] module holds the RFC-agnostic
//! mechanisms (ANONYMOUS, LOGIN, PLAIN, XOAUTH2). The CONDSTORE and
//! QRESYNC extensions (RFC 7162) have no module of their own: they
//! surface as parameters and response fields of the [`rfc3501`]
//! select, examine and fetch coroutines, and power [`watch`]. Code
//! spanning several RFC modules lives at the crate root: [`send`],
//! [`watch`], [`client`] and [`coroutine`].
//!
//! Public types follow the Imap-Target-Verb naming scheme
//! (`ImapMailboxCreate`, `ImapMessageFetchStream`) with Options, Error,
//! Yield and Event companions; single-step coroutines hold the send
//! directly, multi-step ones keep a private State enum.
//!
//! ## The coroutine contract
//!
//! Every coroutine implements [`coroutine::ImapCoroutine`]. Unlike the
//! sibling io-* crates, resume takes two arguments besides self: a
//! borrowed `Fragmentizer` (the connection-wide parser buffer, shared
//! across every coroutine run on that connection so partial reads
//! survive between commands) and the optional input bytes. It returns
//! [`coroutine::ImapCoroutineState`]: either a yield or the terminal
//! result. The [`imap_try!`] macro is the coroutine equivalent of `?`.
//!
//! The standard yield is [`coroutine::ImapYield`]: WantsRead (the
//! caller reads more bytes and feeds them back, `Some(&[])` on EOF) or
//! WantsWrite (the caller writes the given bytes). Coroutines that
//! need richer signals declare their own yield enum: the IDLE and
//! mailbox-watch coroutines add an Event variant, and the streaming
//! APPEND and FETCH coroutines add WantsStream / BodyChunk variants so
//! message bodies move straight between socket and caller storage
//! without landing in memory whole.
//!
//! ## The send primitive
//!
//! Every command-shaped coroutine delegates to one shared primitive:
//! [`send::ImapSend`]. It serialises the command through imap-codec
//! (handling synchronising literals by pausing until the server
//! continuation), then collects the response: data and untagged
//! status lines accumulate, a tagged, bye or continuation-request line
//! terminates, and undecodable untagged lines are skipped instead of
//! failing the whole command. Its terminal value is
//! [`send::ImapSendOutput`]; failures surface as
//! [`send::ImapSendError`]. The receive-only constructor
//! [`send::ImapSend::receive`] parses the response of a request whose
//! bytes were written out of band (used by the streamed APPEND).
//!
//! ## Authentication
//!
//! Each SASL mechanism is its own coroutine supporting both the non-IR
//! and SASL-IR (RFC 4959) flows. Every auth and login coroutine offers
//! an optional auto_id chaining an RFC 2971 ID round-trip right after
//! authentication, required by providers such as mail.qq.com and
//! Fastmail. Secrets ride in imap-types `Secret` wrappers so they never
//! land in logs.
//!
//! ## Watching a mailbox
//!
//! [`watch`] provides `ImapMailboxWatch`, a composite coroutine
//! chaining ENABLE QRESYNC, SELECT (CONDSTORE), a FETCH baseline seed,
//! then an IDLE wake-loop with SELECT (QRESYNC) delta pulls, emitting
//! UID-keyed added/changed/removed events. The connection is dedicated;
//! a shared `AtomicBool` winds it down cleanly.
//!
//! ## The std client
//!
//! [`client::ImapClientStd`] (`client` feature) wraps any blocking
//! `Read + Write` stream plus a per-connection `Fragmentizer`, and
//! exposes one method per coroutine. The connect constructor (TLS
//! features) parses an imap:// or imaps:// URL, opens the connection
//! through pimalaya-stream, performs the optional STARTTLS upgrade,
//! reads the greeting and runs the chosen SASL mechanism.
//!
//! ## Conventions
//!
//! The conventions every Pimalaya repository shares (the sans-I/O
//! coroutine approach, no_std, module and error rules) are described
//! in the [Pimalaya ARCHITECTURE](https://github.com/pimalaya/.github/blob/master/ARCHITECTURE.md)
//! and [GUIDELINES](https://github.com/pimalaya/.github/blob/master/GUIDELINES.md);
//! the Imap-Target-Verb naming above is the org-wide canon, and the
//! [`codec`] / [`types`] root re-exports are its blessed exception for
//! foreign crates the API is built on.
//! Coroutines log through the log crate at two levels: debug carries a
//! short human-readable phrase at state changes, and a trace directly
//! below dumps the data when there is any. Complete runnable programs
//! live in the examples folder, one per layer.

extern crate alloc;
#[cfg(feature = "client")]
extern crate std;

#[cfg(feature = "client")]
pub mod client;
pub mod coroutine;
pub mod rfc2177;
pub mod rfc2971;
pub mod rfc3501;
pub mod rfc3691;
pub mod rfc4315;
pub mod rfc5161;
pub mod rfc5256;
pub mod rfc6851;
pub mod rfc7628;
#[cfg(feature = "scram")]
pub mod rfc7677;
pub mod sasl;
pub mod send;
pub mod watch;

/// The imap-codec crate this version of io-imap builds on, re-exported
/// so consumers encode and decode with the exact same codec version.
pub use imap_codec as codec;
/// The imap-types crate matching [`codec`], re-exported for the same
/// version-lock reason.
///
/// Coroutine inputs and outputs are made of these types.
pub use imap_codec::imap_types as types;

/// Tests whether a capability list advertises a given capability, written as a
/// [`matches!`]-style variant pattern without the `Capability::` prefix.
///
/// Matches by variant, so payload-carrying capabilities are checked with a
/// wildcard: `has_imap_capability!(caps, Sort(_))` is true for both bare `SORT`
/// and `SORT=DISPLAY`.
///
/// ```
/// use io_imap::has_imap_capability;
/// use io_imap::types::response::Capability;
///
/// let caps = [Capability::Move, Capability::Sort(None)];
/// assert!(has_imap_capability!(caps, Sort(_)));
/// assert!(has_imap_capability!(caps, Move));
/// assert!(!has_imap_capability!(caps, Idle));
/// ```
#[macro_export]
macro_rules! has_imap_capability {
    ($caps:expr, $($variant:tt)+) => {
        $caps
            .iter()
            .any(|capability| matches!(capability, $crate::types::response::Capability::$($variant)+))
    };
}
