#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]

#[macro_use]
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

pub use imap_codec as codec;
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
