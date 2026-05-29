//! # Generic coroutine driver
//!
//! Every standard-shape coroutine in this crate exposes the same loop
//! contract: produce some bytes to write, ask for some bytes to read,
//! or terminate with success or failure. The [`ImapCoroutine`] trait
//! unifies that contract behind a single method so a generic driver
//! ([`ImapClientStd::run`]) can advance any coroutine without macros.
//!
//! Coroutines whose progression yields extra intermediate events
//! ([`ImapMailboxWatch`](crate::watch::ImapMailboxWatch),
//! [`ImapIdle`](crate::rfc2177::idle::ImapIdle)) or a different resume
//! signature ([`ImapStartTls`](crate::rfc3501::starttls::ImapStartTls))
//! stay outside this trait and keep their own per-coroutine `Result`
//! enums.
//!
//! [`ImapClientStd::run`]: crate::client::ImapClientStd::run

use alloc::vec::Vec;

use imap_codec::fragmentizer::Fragmentizer;

/// State yielded by an [`ImapCoroutine`] resume.
///
/// Single generic enum so a generic driver can pattern match on
/// progression without naming a per-coroutine `Result` type.
#[derive(Debug)]
pub enum ImapCoroutineState<T, E> {
    /// Coroutine terminated successfully with this payload.
    Done(T),
    /// Caller should read more bytes from the socket and feed them
    /// back on the next resume.
    WantsRead,
    /// Caller should write these bytes to the socket; the next resume
    /// typically takes `None`.
    WantsWrite(Vec<u8>),
    /// Coroutine terminated with this error.
    Err(E),
}

/// Standard-shape IMAP coroutine: anything whose progression maps onto
/// [`ImapCoroutineState`].
///
/// `resume` is the single source of truth: each implementor's body
/// returns [`ImapCoroutineState::Done`] / [`WantsRead`] /
/// [`WantsWrite`] / [`Err`] directly. [`ImapClientStd::run`] drives
/// any [`ImapCoroutine`] to completion against a blocking stream;
/// downstream code can write its own driver against the same trait.
///
/// [`ImapClientStd::run`]: crate::client::ImapClientStd::run
/// [`WantsRead`]: ImapCoroutineState::WantsRead
/// [`WantsWrite`]: ImapCoroutineState::WantsWrite
/// [`Err`]: ImapCoroutineState::Err
pub trait ImapCoroutine {
    /// Payload yielded on terminal success.
    type Output;
    /// Error yielded on terminal failure.
    type Error;

    /// Advances the coroutine one step.
    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Output, Self::Error>;
}
