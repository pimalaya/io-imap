//! Generator-shape coroutine contract, mirroring `core::ops::Coroutine`.
//!
//! `Yield` covers intermediate progress, `Return` the terminal output,
//! [`ImapCoroutineState`] both.

use core::fmt;

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

    /// Pass `None` initially or after a `WantsWrite`, `Some(tag)` after
    /// a `WantsTag`, `Some(bytes)` after a `WantsRead`, `Some(&[])` on
    /// EOF.
    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return>;
}

/// Standard yield variants: the next command tag and socket I/O; pick
/// another type when extra variants (events, etc.) are needed.
pub enum ImapYield {
    /// The caller resumes with the tag of the next command, unique on
    /// the connection.
    WantsTag,
    /// The caller reads from its stream and resumes with the bytes.
    WantsRead,
    /// The caller writes the given bytes to its stream and resumes.
    WantsWrite(Vec<u8>),
}

impl fmt::Debug for ImapYield {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WantsTag => f.write_str("WantsTag"),
            Self::WantsRead => f.write_str("WantsRead"),
            // NOTE: a write may hold credentials, its length does not.
            Self::WantsWrite(bytes) => write!(f, "WantsWrite({} octets)", bytes.len()),
        }
    }
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

#[cfg(test)]
mod tests {
    use alloc::format;

    use crate::coroutine::*;

    #[test]
    fn debug_of_a_write_prints_its_length_only() {
        let yielded = ImapYield::WantsWrite(b"A1 LOGIN alice secret\r\n".to_vec());
        assert_eq!("WantsWrite(23 octets)", format!("{yielded:?}"));
    }
}
