//! IMAP COPY coroutine surfacing the optional COPYUID code.
//!
//! # Example
//!
//! ```rust,no_run
//! use std::{
//!     io::{Read, Write},
//!     net::TcpStream,
//! };
//!
//! use io_imap::{
//!     codec::{fragmentizer::Fragmentizer, imap_types::core::TagGenerator},
//!     coroutine::{ImapCoroutine, ImapCoroutineState, ImapYield},
//!     rfc3501::copy::{ImapMessageCopy, ImapMessageCopyOptions},
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negotiated, IMAP-authenticated)
//! let mut stream = TcpStream::connect("localhost:143").unwrap();
//!
//! let mut fragmentizer = Fragmentizer::new(50 * 1024 * 1024);
//! let mut buf = [0u8; 4096];
//!
//! let sequence_set = "1:3".try_into().unwrap();
//! let mailbox = "Archive".try_into().unwrap();
//! let opts = ImapMessageCopyOptions::default();
//! let mut coroutine = ImapMessageCopy::new(sequence_set, mailbox, opts);
//! let mut tags = TagGenerator::new();
//! let mut tag;
//! let mut arg = None;
//!
//! let copyuid = loop {
//!     match coroutine.resume(&mut fragmentizer, arg.take()) {
//!         ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         ImapCoroutineState::Yielded(ImapYield::WantsTag) => {
//!             tag = tags.generate();
//!             arg = Some(tag.as_ref().as_bytes());
//!         }
//!         ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         ImapCoroutineState::Complete(Ok(copyuid)) => break copyuid,
//!         ImapCoroutineState::Complete(Err(err)) => panic!("{err}"),
//!     }
//! };
//!
//! println!("{copyuid:?}");
//! ```

use core::{fmt, num::NonZeroU32, ops::RangeInclusive};

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        command::CommandBody,
        core::Vec1,
        extensions::uidplus::{UidElement, UidSet},
        mailbox::Mailbox,
        response::{Code, StatusKind, Tagged},
        sequence::SequenceSet,
    },
};
use log::{debug, trace};
use thiserror::Error;

use crate::{coroutine::*, imap_try, rfc3501::mailbox::encode_inplace, send::*};

/// COPYUID response code of COPY and MOVE: the UIDs of the copied
/// messages, source and destination paired in the order of the code.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc4315#section-3>
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImapCopyUid {
    /// UIDVALIDITY of the destination mailbox, `0` when the server sent
    /// that forbidden value.
    pub uid_validity: u32,
    /// Source UIDs, as ascending ranges in the order of the code.
    pub source: Vec<RangeInclusive<NonZeroU32>>,
    /// Destination UIDs, as ascending ranges in the order of the code.
    pub destination: Vec<RangeInclusive<NonZeroU32>>,
}

impl ImapCopyUid {
    /// Builds the code from its two sets, never expanded; `None` when
    /// they do not hold the same number of UIDs.
    fn from_sets(uid_validity: u32, source: UidSet, destination: UidSet) -> Option<Self> {
        let copyuid = Self {
            uid_validity,
            source: uid_ranges(source),
            destination: uid_ranges(destination),
        };

        if uid_count(&copyuid.source) != uid_count(&copyuid.destination) {
            debug!("skipping COPYUID whose sets differ in length");
            return None;
        }

        Some(copyuid)
    }

    /// Number of copied messages, which a server may announce in the
    /// billions: check it before collecting [`Self::pairs`].
    pub fn count(&self) -> u64 {
        uid_count(&self.source)
    }

    /// Iterates lazily over the `(source, destination)` UID pairs.
    pub fn pairs(&self) -> impl Iterator<Item = (NonZeroU32, NonZeroU32)> + '_ {
        uids(&self.source).zip(uids(&self.destination))
    }
}

/// Failure causes during the IMAP COPY flow.
#[derive(Clone, Debug, Error)]
pub enum ImapMessageCopyError {
    /// The server rejected the command with a NO response.
    #[error("IMAP COPY failed: NO {0}")]
    No(String),
    /// The server rejected the command with a BAD response.
    #[error("IMAP COPY failed: BAD {0}")]
    Bad(String),
    /// The server closed the session with an untagged BYE.
    #[error("IMAP COPY failed: BYE {0}")]
    Bye(String),
    /// The exchange ended without a tagged response from the server.
    #[error("IMAP COPY failed: server did not return a tagged response")]
    MissingTagged,
    /// The underlying send/receive exchange failed (EOF, decode, framing).
    #[error("IMAP COPY failed: {0}")]
    Send(#[from] ImapSendError),
}

/// Options for [`ImapMessageCopy::new`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImapMessageCopyOptions {
    /// When `true`, send `UID COPY` and treat `sequence_set` as UIDs.
    pub uid: bool,
}

/// I/O-free IMAP COPY coroutine.
pub struct ImapMessageCopy {
    state: State,
}

impl ImapMessageCopy {
    /// Builds a COPY coroutine copying the `sequence_set` messages to
    /// `mailbox`.
    pub fn new(
        sequence_set: SequenceSet,
        mut mailbox: Mailbox<'static>,
        opts: ImapMessageCopyOptions,
    ) -> Self {
        encode_inplace(&mut mailbox);

        let body = CommandBody::Copy {
            sequence_set,
            mailbox,
            uid: opts.uid,
        };

        trace!("send IMAP command {body:?}");

        let state = State::Send(ImapSend::command(body));

        Self { state }
    }
}

impl ImapCoroutine for ImapMessageCopy {
    type Yield = ImapYield;
    type Return = Result<Option<ImapCopyUid>, ImapMessageCopyError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        match &mut self.state {
            State::Send(send) => {
                let out = imap_try!(send, fragmentizer, arg);

                if let Some(bye) = out.bye {
                    let err = ImapMessageCopyError::Bye(bye.text.to_string());
                    return ImapCoroutineState::Complete(Err(err));
                }

                let Some(Tagged { body, .. }) = out.tagged else {
                    let err = ImapMessageCopyError::MissingTagged;
                    return ImapCoroutineState::Complete(Err(err));
                };

                match body.kind {
                    StatusKind::Ok => {
                        let copyuid = copyuid_from_code(body.code);
                        ImapCoroutineState::Complete(Ok(copyuid))
                    }
                    StatusKind::No => {
                        let err = ImapMessageCopyError::No(body.text.to_string());
                        ImapCoroutineState::Complete(Err(err))
                    }
                    StatusKind::Bad => {
                        let err = ImapMessageCopyError::Bad(body.text.to_string());
                        ImapCoroutineState::Complete(Err(err))
                    }
                }
            }
        }
    }
}

enum State {
    Send(ImapSend<CommandCodec>),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(_) => f.write_str("send copy"),
        }
    }
}

/// Extracts the COPYUID from a response code, whether it rode a tagged
/// or an untagged OK; shared with MOVE.
///
/// A COPYUID the strict grammar rejects reaches here as [`Code::Other`]
/// and is read again by [`copyuid_from_other`], so a known server
/// deviation keeps its UID mapping. Any other code gives `None`.
pub(crate) fn copyuid_from_code(code: Option<Code<'_>>) -> Option<ImapCopyUid> {
    match code? {
        Code::CopyUid {
            uid_validity,
            source,
            destination,
        } => ImapCopyUid::from_sets(uid_validity.get(), source, destination),
        Code::Other(other) => copyuid_from_other(other.inner()),
        _ => None,
    }
}

/// Reads a COPYUID whose UIDVALIDITY is `0`.
///
/// RFC 4315 §3 defines the code as `"COPYUID" SP nz-number SP uid-set
/// SP uid-set`, but some servers, such as Mailo, send a UIDVALIDITY of
/// `0`, so imap-codec leaves the whole code unparsed. This accepts
/// exactly that deviation: the UIDVALIDITY may be the single digit
/// `0`, everything else follows the grammar (no leading zero, no `*`,
/// no UID `0`, a single space between the fields, nothing after the
/// destination set). Anything else stays unreadable and gives `None`.
fn copyuid_from_other(bytes: &[u8]) -> Option<ImapCopyUid> {
    let mut fields = bytes.split(|b| *b == b' ');

    if !fields.next()?.eq_ignore_ascii_case(b"COPYUID") {
        return None;
    }

    let uid_validity = match fields.next()? {
        b"0" => 0,
        field => nz_number(field)?.get(),
    };
    let source = uid_set(fields.next()?)?;
    let destination = uid_set(fields.next()?)?;

    if fields.next().is_some() {
        return None;
    }

    debug!("read COPYUID with UIDVALIDITY {uid_validity}, rejected by the strict grammar");

    ImapCopyUid::from_sets(uid_validity, source, destination)
}

/// `uid-set = (uniqueid / uid-range) *("," uid-set)` (RFC 4315 §4).
fn uid_set(bytes: &[u8]) -> Option<UidSet> {
    let mut elements = Vec::new();

    for element in bytes.split(|b| *b == b',') {
        let element = match element.iter().position(|b| *b == b':') {
            Some(colon) => UidElement::Range(
                nz_number(&element[..colon])?,
                nz_number(&element[colon + 1..])?,
            ),
            None => UidElement::Single(nz_number(element)?),
        };
        elements.push(element);
    }

    Some(UidSet(Vec1::try_from(elements).ok()?))
}

/// `nz-number = digit-nz *DIGIT` (RFC 3501 §9), within a `u32`.
fn nz_number(bytes: &[u8]) -> Option<NonZeroU32> {
    let (first, _) = bytes.split_first()?;

    if !matches!(first, b'1'..=b'9') || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }

    core::str::from_utf8(bytes).ok()?.parse().ok()
}

/// Reads a `uid-set` as ranges in wire order, never expanded; a range
/// is ascending whichever way it is written (RFC 4315 §4).
fn uid_ranges(uid_set: UidSet) -> Vec<RangeInclusive<NonZeroU32>> {
    let ranges = uid_set.0.into_iter().map(|element| match element {
        UidElement::Single(uid) => uid..=uid,
        UidElement::Range(a, b) => a.min(b)..=a.max(b),
    });

    ranges.collect()
}

/// Number of UIDs the ranges hold.
fn uid_count(ranges: &[RangeInclusive<NonZeroU32>]) -> u64 {
    let counts = ranges
        .iter()
        .map(|range| u64::from(range.end().get() - range.start().get()) + 1);

    counts.sum()
}

/// Iterates lazily over the UIDs the ranges hold.
fn uids(ranges: &[RangeInclusive<NonZeroU32>]) -> impl Iterator<Item = NonZeroU32> + '_ {
    ranges
        .iter()
        .flat_map(|range| range.start().get()..=range.end().get())
        .filter_map(NonZeroU32::new)
}

#[cfg(test)]
mod tests {
    use core::str;

    use alloc::{borrow::ToOwned, format, vec};

    use crate::rfc3501::copy::*;

    #[test]
    fn success_with_copyuid_returns_uids() {
        let mut copy = ImapMessageCopy::new(
            "1:3".try_into().expect("valid sequence set"),
            "Archive".try_into().expect("valid mailbox"),
            ImapMessageCopyOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        expect_wants_tag(&mut copy, &mut frag);
        let bytes = expect_wants_write(&mut copy, &mut frag, Some(b"A1"));
        let line = str::from_utf8(&bytes).expect("utf8 command");
        let tag = first_word(line).to_owned();
        assert!(line.contains("COPY 1:3 Archive"));

        expect_wants_read(&mut copy, &mut frag);

        let reply = format!("{tag} OK [COPYUID 1700 1:3 10:12] COPY completed\r\n");
        let copyuid = expect_complete_ok(&mut copy, &mut frag, reply.as_bytes())
            .expect("server returned COPYUID");
        assert_eq!(1700, copyuid.uid_validity);
        assert_eq!(vec![(1, 10), (2, 11), (3, 12)], pairs(&copyuid));
    }

    #[test]
    fn success_with_uidvalidity_zero_returns_uids() {
        let mut copy = ImapMessageCopy::new(
            "1582".try_into().expect("valid sequence set"),
            "Archive".try_into().expect("valid mailbox"),
            ImapMessageCopyOptions { uid: true },
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        expect_wants_tag(&mut copy, &mut frag);
        let bytes = expect_wants_write(&mut copy, &mut frag, Some(b"A1"));
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read(&mut copy, &mut frag);

        // NOTE: Mailo's answer (pimalaya/himalaya#781): RFC 4315 forbids
        // the UIDVALIDITY 0, so imap-codec leaves the code unparsed.
        let reply = format!("{tag} OK [COPYUID 0 1582 22704] UID COPY done\r\n");
        let copyuid = expect_complete_ok(&mut copy, &mut frag, reply.as_bytes())
            .expect("UIDVALIDITY 0 COPYUID read");
        assert_eq!(0, copyuid.uid_validity);
        assert_eq!(vec![(1582, 22704)], pairs(&copyuid));
    }

    #[test]
    fn success_with_garbage_copyuid_returns_none() {
        let mut copy = ImapMessageCopy::new(
            "1".try_into().expect("valid sequence set"),
            "Archive".try_into().expect("valid mailbox"),
            ImapMessageCopyOptions { uid: true },
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        expect_wants_tag(&mut copy, &mut frag);
        let bytes = expect_wants_write(&mut copy, &mut frag, Some(b"A1"));
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read(&mut copy, &mut frag);

        let reply = format!("{tag} OK [COPYUID 0 0 22704] UID COPY done\r\n");
        let copyuid = expect_complete_ok(&mut copy, &mut frag, reply.as_bytes());
        assert!(copyuid.is_none());
    }

    #[test]
    fn lenient_copyuid_takes_only_uidvalidity_zero() {
        let read = |code: &str| {
            let copyuid = copyuid_from_other(code.as_bytes())?;
            Some((copyuid.uid_validity, pairs(&copyuid)))
        };

        assert_eq!(Some((0, vec![(1582, 22704)])), read("COPYUID 0 1582 22704"));
        assert_eq!(
            Some((0, vec![(1, 10), (2, 11), (3, 12), (7, 13)])),
            read("copyuid 0 1:3,7 10:13"),
        );
        assert_eq!(Some((0, vec![(2, 5), (3, 6)])), read("COPYUID 0 3:2 6:5"));

        for garbage in [
            "",
            "COPYUID",
            "COPYUID 0",
            "COPYUID 0 1582",
            "COPYUID 0 1582 22704 extra",
            "COPYUID 0 1582 22704 ",
            "COPYUID  0 1582 22704",
            "COPYUID 00 1582 22704",
            "COPYUID -0 1582 22704",
            "COPYUID +1 1582 22704",
            "COPYUID 4294967296 1582 22704",
            "COPYUID x 1582 22704",
            "COPYUID 0 0 22704",
            "COPYUID 0 01582 22704",
            "COPYUID 0 1582 *",
            "COPYUID 0 1582: 22704",
            "COPYUID 0 1:2:3 22704",
            "COPYUID 0 1582, 22704",
            "COPYUID 0 ,1582 22704",
            "COPYUIDX 0 1582 22704",
            "APPENDUID 0 1582",
            "UIDVALIDITY 0",
        ] {
            assert_eq!(None, read(garbage), "{garbage:?} read as COPYUID");
        }
    }

    #[test]
    fn copyuid_ranges_stay_unexpanded() {
        let mut copy = ImapMessageCopy::new(
            "1".try_into().expect("valid sequence set"),
            "Archive".try_into().expect("valid mailbox"),
            ImapMessageCopyOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        expect_wants_tag(&mut copy, &mut frag);
        let _ = expect_wants_write(&mut copy, &mut frag, Some(b"A1"));
        expect_wants_read(&mut copy, &mut frag);

        let reply = b"A1 OK [COPYUID 1 1:4294967295 4294967295:1] done\r\n";
        let copyuid = expect_complete_ok(&mut copy, &mut frag, reply).expect("COPYUID");
        let whole = NonZeroU32::MIN..=NonZeroU32::MAX;
        assert_eq!(vec![whole.clone()], copyuid.source);
        assert_eq!(vec![whole], copyuid.destination);
        assert_eq!(4294967295, copyuid.count());
    }

    #[test]
    fn copyuid_pairs_follow_wire_order() {
        let mut copy = ImapMessageCopy::new(
            "5,3".try_into().expect("valid sequence set"),
            "Archive".try_into().expect("valid mailbox"),
            ImapMessageCopyOptions { uid: true },
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        expect_wants_tag(&mut copy, &mut frag);
        let _ = expect_wants_write(&mut copy, &mut frag, Some(b"A1"));
        expect_wants_read(&mut copy, &mut frag);

        let reply = b"A1 OK [COPYUID 7 5,3 10:11] done\r\n";
        let copyuid = expect_complete_ok(&mut copy, &mut frag, reply).expect("COPYUID");
        assert_eq!(vec![(5, 10), (3, 11)], pairs(&copyuid));
    }

    #[test]
    fn copyuid_sets_of_different_lengths_give_none() {
        let mut copy = ImapMessageCopy::new(
            "1:3".try_into().expect("valid sequence set"),
            "Archive".try_into().expect("valid mailbox"),
            ImapMessageCopyOptions { uid: true },
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        expect_wants_tag(&mut copy, &mut frag);
        let _ = expect_wants_write(&mut copy, &mut frag, Some(b"A1"));
        expect_wants_read(&mut copy, &mut frag);

        let reply = b"A1 OK [COPYUID 7 1:3 10:11] done\r\n";
        assert_eq!(None, expect_complete_ok(&mut copy, &mut frag, reply));
        assert_eq!(None, copyuid_from_other(b"COPYUID 0 1:3 10:11"));
    }

    #[test]
    fn uid_variant_sends_uid_copy() {
        let mut copy = ImapMessageCopy::new(
            "42".try_into().expect("valid sequence set"),
            "Archive".try_into().expect("valid mailbox"),
            ImapMessageCopyOptions { uid: true },
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        expect_wants_tag(&mut copy, &mut frag);
        let bytes = expect_wants_write(&mut copy, &mut frag, Some(b"A1"));
        let line = str::from_utf8(&bytes).expect("utf8 command");
        assert!(line.contains("UID COPY 42 Archive"));
    }

    #[test]
    fn success_without_copyuid_returns_none() {
        let mut copy = ImapMessageCopy::new(
            "1".try_into().expect("valid sequence set"),
            "Archive".try_into().expect("valid mailbox"),
            ImapMessageCopyOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        expect_wants_tag(&mut copy, &mut frag);
        let bytes = expect_wants_write(&mut copy, &mut frag, Some(b"A1"));
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read(&mut copy, &mut frag);

        let reply = format!("{tag} OK COPY completed\r\n");
        let copyuid = expect_complete_ok(&mut copy, &mut frag, reply.as_bytes());
        assert!(copyuid.is_none());
    }

    #[test]
    fn tagged_no_returns_no_error() {
        let mut copy = ImapMessageCopy::new(
            "1".try_into().expect("valid sequence set"),
            "Archive".try_into().expect("valid mailbox"),
            ImapMessageCopyOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        expect_wants_tag(&mut copy, &mut frag);
        let bytes = expect_wants_write(&mut copy, &mut frag, Some(b"A1"));
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read(&mut copy, &mut frag);

        let reply = format!("{tag} NO destination mailbox does not exist\r\n");
        let err = expect_complete_err(&mut copy, &mut frag, reply.as_bytes());
        let ImapMessageCopyError::No(text) = err else {
            panic!("expected ImapMessageCopyError::No, got {err:?}");
        };
        assert_eq!(text, "destination mailbox does not exist");
    }

    #[test]
    fn bye_returns_bye_error() {
        let mut copy = ImapMessageCopy::new(
            "1".try_into().expect("valid sequence set"),
            "Archive".try_into().expect("valid mailbox"),
            ImapMessageCopyOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        expect_wants_tag(&mut copy, &mut frag);
        let _ = expect_wants_write(&mut copy, &mut frag, Some(b"A1"));
        expect_wants_read(&mut copy, &mut frag);

        let err = expect_complete_err(&mut copy, &mut frag, b"* BYE going down\r\n");
        let ImapMessageCopyError::Bye(text) = err else {
            panic!("expected ImapMessageCopyError::Bye, got {err:?}");
        };
        assert_eq!(text, "going down");
    }

    fn expect_wants_tag(cor: &mut ImapMessageCopy, frag: &mut Fragmentizer) {
        match cor.resume(frag, None) {
            ImapCoroutineState::Yielded(ImapYield::WantsTag) => {}
            state => panic!("expected WantsTag, got {state:?}"),
        }
    }

    fn expect_wants_write(
        cor: &mut ImapMessageCopy,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> Vec<u8> {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ImapMessageCopy, frag: &mut Fragmentizer) {
        match cor.resume(frag, None) {
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(
        cor: &mut ImapMessageCopy,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> Option<ImapCopyUid> {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Complete(Ok(value)) => value,
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn pairs(copyuid: &ImapCopyUid) -> Vec<(u32, u32)> {
        let pairs = copyuid.pairs();
        pairs.map(|(src, dst)| (src.get(), dst.get())).collect()
    }

    fn expect_complete_err(
        cor: &mut ImapMessageCopy,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> ImapMessageCopyError {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        }
    }

    fn first_word(line: &str) -> &str {
        line.split_whitespace()
            .next()
            .expect("first whitespace-separated token")
    }
}
