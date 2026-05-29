//! # Generator-shape coroutine driver
//!
//! Mirrors the shape of core::ops::Coroutine: a `Yield` associated
//! type for intermediate progress, a `Return` associated type for
//! terminal output, and a two-variant [`ImapCoroutineState`]
//! (`Yielded` / `Complete`).
//!
//! Each coroutine declares its own `Yield` enum mixing socket I/O step
//! requests with any extra intermediate variants (e.g.
//! [`ImapStartTlsYield::WantsStartTls`], [`ImapIdleYield::Event`],
//! [`ImapMailboxWatchYield::Event`]). Most request/response coroutines
//! pick the standard [`ImapYield`] directly; only coroutines that need
//! extra variants declare their own.
//!
//! [`ImapClientStd::run`] drives any standard-Yield coroutine to
//! completion against a blocking stream; coroutines that need extra
//! Yield variants get their own per-method client loops.
//!
//! [`ImapClientStd::run`]: crate::client::ImapClientStd::run
//! [`ImapStartTlsYield::WantsStartTls`]: crate::rfc3501::starttls::ImapStartTlsYield::WantsStartTls
//! [`ImapIdleYield::Event`]: crate::rfc2177::idle::ImapIdleYield::Event
//! [`ImapMailboxWatchYield::Event`]: crate::watch::ImapMailboxWatchYield::Event

use alloc::vec::Vec;

use imap_codec::fragmentizer::Fragmentizer;

/// State yielded by an [`ImapCoroutine::resume`] step.
///
/// Two-variant by design (matches std's `core::ops::CoroutineState`):
/// any further variation lives inside the per-coroutine `Yield` type.
#[derive(Debug)]
pub enum ImapCoroutineState<Y, R> {
    /// Intermediate yield. The driver reacts to `Y` (do I/O, deliver
    /// an event...) and resumes the coroutine again.
    Yielded(Y),
    /// Terminal yield. By convention `R = Result<Output, Error>`.
    Complete(R),
}

/// Standard-shape IMAP coroutine.
///
/// Implementors own their internal state machine and declare their
/// per-step `Yield` plus a terminal `Return`. The driver pumps I/O
/// based on the `Yield` variant and resumes until `Complete`.
pub trait ImapCoroutine {
    /// Intermediate value handed back on every step. Per-coroutine:
    /// each implementor picks exactly the variants it needs (socket
    /// I/O, domain events, TLS upgrade requests...).
    type Yield;
    /// Terminal value. By convention `Result<Output, Error>`; the
    /// "ok" arm carries the operation's final output, the "error" arm
    /// carries the cause.
    type Return;

    /// Advances the coroutine one step.
    ///
    /// Pass [`None`] when there is no data to provide (initial call
    /// or after the previous yield was [`ImapYield::WantsWrite`]).
    /// Pass `Some(data)` with bytes read from the socket after a
    /// [`ImapYield::WantsRead`]. Pass `Some(&[])` to signal EOF.
    ///
    /// `fragmentizer` is borrowed from the caller (typically the
    /// per-connection one owned by [`ImapClientStd`]) so its
    /// in-flight server-response buffer survives across resume calls
    /// and coroutine boundaries.
    ///
    /// [`ImapClientStd`]: crate::client::ImapClientStd
    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return>;
}

/// Standard I/O-only Yield. Pick `type Yield = ImapYield` for any
/// coroutine that only needs to read or write socket bytes.
#[derive(Debug)]
pub enum ImapYield {
    /// Driver should read more bytes from the socket and feed them
    /// back on the next resume.
    WantsRead,
    /// Driver should write these bytes to the socket; the next resume
    /// typically takes `None`.
    WantsWrite(Vec<u8>),
}
