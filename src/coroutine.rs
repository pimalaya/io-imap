//! Generator-shape coroutine contract, mirroring `core::ops::Coroutine`.
//!
//! `Yield` covers intermediate progress, `Return` the terminal output,
//! [`ImapCoroutineState`] both.

use alloc::vec::Vec;

use imap_codec::fragmentizer::Fragmentizer;

/// Result of one [`ImapCoroutine::resume`] step.
#[derive(Debug)]
pub enum ImapCoroutineState<Y, R> {
    /// The coroutine needs I/O (or emitted an event) before it can
    /// progress.
    Yielded(Y),
    /// The coroutine is done; resuming it again is a logic error.
    Complete(R),
}

/// An I/O-free IMAP coroutine, resumed with the connection-wide
/// `Fragmentizer` and the bytes read by the caller.
pub trait ImapCoroutine {
    /// The request type yielded while the coroutine progresses.
    type Yield;

    /// The final value produced on completion.
    type Return;

    /// Pass `None` initially or after a `WantsWrite`, `Some(bytes)`
    /// after a `WantsRead`, `Some(&[])` on EOF.
    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return>;
}

/// Standard socket-I/O yield variants; pick another type when extra
/// variants (events, etc.) are needed.
#[derive(Debug)]
pub enum ImapYield {
    /// The caller reads from its stream and resumes with the bytes.
    WantsRead,
    /// The caller writes the given bytes to its stream and resumes.
    WantsWrite(Vec<u8>),
}

/// Coroutine `?`: forwards `Yielded` (via `Into`), short-circuits on
/// `Err`, evaluates to the inner `Ok` value.
#[macro_export]
macro_rules! imap_try {
    ($coroutine:expr, $frag:expr, $arg:expr $(,)?) => {
        match $crate::coroutine::ImapCoroutine::resume($coroutine, $frag, $arg) {
            $crate::coroutine::ImapCoroutineState::Yielded(y) => {
                return $crate::coroutine::ImapCoroutineState::Yielded(y.into());
            }
            $crate::coroutine::ImapCoroutineState::Complete(Err(err)) => {
                return $crate::coroutine::ImapCoroutineState::Complete(Err(err.into()));
            }
            $crate::coroutine::ImapCoroutineState::Complete(Ok(value)) => value,
        }
    };
}
