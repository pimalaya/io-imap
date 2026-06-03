//! Generator-shape coroutine driver. Mirrors `core::ops::Coroutine`:
//! `Yield` for intermediate progress, `Return` for terminal output,
//! [`ImapCoroutineState`] for both.

use alloc::vec::Vec;

use imap_codec::fragmentizer::Fragmentizer;

/// Result of one [`ImapCoroutine::resume`] step.
#[derive(Debug)]
pub enum ImapCoroutineState<Y, R> {
    Yielded(Y),
    Complete(R),
}

pub trait ImapCoroutine {
    type Yield;
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
    WantsRead,
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
