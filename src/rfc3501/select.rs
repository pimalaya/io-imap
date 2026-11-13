//! IMAP SELECT coroutine; accepts SELECT parameters (RFC 4466) to opt
//! into CONDSTORE/QRESYNC extras.
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
//!     rfc3501::select::{ImapMailboxSelect, ImapMailboxSelectOptions},
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negotiated, IMAP-authenticated)
//! let mut stream = TcpStream::connect("localhost:143").unwrap();
//!
//! let mut fragmentizer = Fragmentizer::new(50 * 1024 * 1024);
//! let mut buf = [0u8; 4096];
//!
//! let mailbox = "INBOX".try_into().unwrap();
//! let opts = ImapMailboxSelectOptions::default();
//! let mut coroutine = ImapMailboxSelect::new(mailbox, opts);
//! let mut tags = TagGenerator::new();
//! let mut tag;
//! let mut arg = None;
//!
//! let data = loop {
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
//!         ImapCoroutineState::Complete(Ok(out)) => break out.data,
//!         ImapCoroutineState::Complete(Err(err)) => panic!("{err}"),
//!     }
//! };
//!
//! println!("{data:?}");
//! ```

use core::{fmt, num::NonZeroU32, ops::RangeInclusive};

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        command::{CommandBody, SelectParameter},
        core::Vec1,
        fetch::MessageDataItem,
        flag::{Flag, FlagPerm},
        mailbox::Mailbox,
        response::{Code, Data, StatusBody, StatusKind, Tagged},
        sequence::{Sequence, SequenceSet},
    },
};
use log::trace;
use thiserror::Error;

use crate::{coroutine::*, imap_try, rfc3501::mailbox::encode_inplace, send::*};

/// Failure causes during the IMAP SELECT flow.
#[derive(Clone, Debug, Error)]
pub enum ImapMailboxSelectError {
    /// The server rejected the command with a NO response.
    #[error("IMAP SELECT failed: NO {0}")]
    No(ImapStatusError),
    /// The server rejected the command with a BAD response.
    #[error("IMAP SELECT failed: BAD {0}")]
    Bad(ImapStatusError),
    /// The server closed the session with an untagged BYE.
    #[error("IMAP SELECT failed: BYE {0}")]
    Bye(String),
    /// The exchange ended without a tagged response from the server.
    #[error("IMAP SELECT failed: server did not return a tagged response")]
    MissingTagged,
    /// The underlying send/receive exchange failed (EOF, decode, framing).
    #[error("IMAP SELECT failed: {0}")]
    Send(#[from] ImapSendError),
}

/// Decoded SELECT (or EXAMINE) response.
///
/// CONDSTORE/QRESYNC extras (`highest_mod_seq`, `vanished_earlier`,
/// `changed`) stay empty on the base call.
#[derive(Clone, Debug, Default)]
pub struct ImapMailboxSelectData {
    /// Flags defined in the mailbox (untagged FLAGS).
    pub flags: Option<Vec<Flag<'static>>>,
    /// Number of messages in the mailbox (untagged EXISTS).
    pub exists: Option<u32>,
    /// Number of messages with the `\Recent` flag (untagged RECENT).
    pub recent: Option<u32>,
    /// Sequence number of the first unseen message (UNSEEN code).
    pub unseen: Option<NonZeroU32>,
    /// Flags the client can change permanently (PERMANENTFLAGS code).
    pub permanent_flags: Option<Vec<FlagPerm<'static>>>,
    /// Predicted UID of the next message (UIDNEXT code).
    pub uid_next: Option<NonZeroU32>,
    /// UID validity of the mailbox (UIDVALIDITY code).
    pub uid_validity: Option<NonZeroU32>,
    /// Highest modification sequence (CONDSTORE HIGHESTMODSEQ code).
    pub highest_mod_seq: Option<u64>,
    /// UIDs expunged since the last sync (QRESYNC `VANISHED (EARLIER)`),
    /// kept as the inclusive ranges the server announced.
    pub vanished_earlier: Vec<RangeInclusive<NonZeroU32>>,
    /// Implicit FETCH responses for changed messages (QRESYNC).
    pub changed: Vec<ImapMailboxSelectFetch>,
    /// Whether the mailbox was opened read-only (READ-ONLY or
    /// READ-WRITE code of the completion), `None` when the server
    /// said neither.
    pub read_only: Option<bool>,
    /// Whether the mailbox keeps no modification sequences (NOMODSEQ
    /// code).
    pub no_mod_seq: bool,
}

impl ImapMailboxSelectData {
    /// Reads what a response code says of the opened mailbox itself.
    pub(crate) fn read_access_code(&mut self, code: Option<&Code<'_>>) {
        match code {
            Some(Code::ReadOnly) => self.read_only = Some(true),
            Some(Code::ReadWrite) => self.read_only = Some(false),
            Some(Code::NoModSeq) => self.no_mod_seq = true,
            _ => {}
        }
    }
}

/// Implicit FETCH returned during a QRESYNC SELECT.
#[derive(Clone, Debug)]
pub struct ImapMailboxSelectFetch {
    /// Sequence number of the changed message.
    pub seq: NonZeroU32,
    /// FETCH data items carried by the response.
    pub items: Vec1<MessageDataItem<'static>>,
}

/// Options for [`ImapMailboxSelect::new`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImapMailboxSelectOptions {
    /// SELECT/EXAMINE parameters (RFC 4466), e.g. CONDSTORE/QRESYNC.
    pub parameters: Vec<SelectParameter>,
}

/// I/O-free IMAP SELECT coroutine.
pub struct ImapMailboxSelect {
    state: State,
}

impl ImapMailboxSelect {
    /// Builds a SELECT coroutine opening `mailbox` read-write;
    /// `opts.parameters` opts into CONDSTORE/QRESYNC extras.
    pub fn new(mut mailbox: Mailbox<'static>, opts: ImapMailboxSelectOptions) -> Self {
        encode_inplace(&mut mailbox);

        let body = CommandBody::Select {
            mailbox,
            parameters: opts.parameters,
        };

        trace!("send IMAP command {body:?}");

        let state = State::Send(ImapSend::command(body));

        Self { state }
    }
}

impl ImapCoroutine for ImapMailboxSelect {
    type Yield = ImapYield;
    type Return = Result<ImapOutput<ImapMailboxSelectData>, ImapMailboxSelectError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        match &mut self.state {
            State::Send(send) => {
                let out = imap_try!(send, fragmentizer, arg);
                let alerts = out.alerts();

                if let Some(bye) = out.bye {
                    let err = ImapMailboxSelectError::Bye(bye.text.to_string());
                    return ImapCoroutineState::Complete(Err(err));
                }

                let Some(Tagged { body, .. }) = out.tagged else {
                    let err = ImapMailboxSelectError::MissingTagged;
                    return ImapCoroutineState::Complete(Err(err));
                };

                let mut output = ImapMailboxSelectData::default();

                for data in out.data {
                    match data {
                        Data::Flags(flags) => output.flags = Some(flags),
                        Data::Exists(count) => output.exists = Some(count),
                        Data::Recent(count) => output.recent = Some(count),
                        Data::Fetch { seq, items } => {
                            output.changed.push(ImapMailboxSelectFetch { seq, items });
                        }
                        Data::Vanished {
                            earlier,
                            known_uids,
                        } if earlier => {
                            output.vanished_earlier.extend(uid_ranges(&known_uids));
                        }
                        _ => {}
                    }
                }

                output.read_access_code(body.code.as_ref());

                for StatusBody { kind, code, .. } in out.untagged {
                    if let StatusKind::Ok = kind {
                        output.read_access_code(code.as_ref());

                        match code {
                            Some(Code::Unseen(seq)) => output.unseen = Some(seq),
                            Some(Code::PermanentFlags(flags)) => {
                                output.permanent_flags = Some(flags)
                            }
                            Some(Code::UidNext(uid)) => output.uid_next = Some(uid),
                            Some(Code::UidValidity(uid)) => output.uid_validity = Some(uid),
                            Some(Code::HighestModSeq(modseq)) => {
                                output.highest_mod_seq = Some(modseq.get());
                            }
                            _ => {}
                        }
                    }
                }

                match body.kind {
                    StatusKind::Ok => ImapCoroutineState::Complete(Ok(ImapOutput {
                        data: output,
                        alerts,
                        skipped: out.skipped,
                    })),
                    StatusKind::No => {
                        let err = ImapMailboxSelectError::No(body.into());
                        ImapCoroutineState::Complete(Err(err))
                    }
                    StatusKind::Bad => {
                        let err = ImapMailboxSelectError::Bad(body.into());
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
            Self::Send(_) => f.write_str("send select"),
        }
    }
}

/// Reads a `VANISHED (EARLIER)` uid-set as inclusive ranges, never
/// expanded: a server may announce any span, such as `1:4294967295`.
///
/// RFC 7162 §3.2.10 forbids `*`; one read anyway stands for the largest
/// UID. Reversed ranges (`9:3`) are normalised.
pub(crate) fn uid_ranges(
    uid_set: &SequenceSet,
) -> impl Iterator<Item = RangeInclusive<NonZeroU32>> + '_ {
    uid_set.0.as_ref().iter().map(|seq| match seq {
        Sequence::Single(uid) => {
            let uid = uid.expand(NonZeroU32::MAX);
            uid..=uid
        }
        Sequence::Range(a, b) => {
            let a = a.expand(NonZeroU32::MAX);
            let b = b.expand(NonZeroU32::MAX);
            a.min(b)..=a.max(b)
        }
    })
}

#[cfg(test)]
mod tests {
    use core::str;

    use alloc::{borrow::ToOwned, format, vec::Vec};

    use crate::rfc3501::select::*;

    #[test]
    fn success_collects_response() {
        let mut select = ImapMailboxSelect::new(
            "INBOX".try_into().expect("valid mailbox"),
            ImapMailboxSelectOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        expect_wants_tag(&mut select, &mut frag);
        let bytes = expect_wants_write(&mut select, &mut frag, Some(b"A1"));
        let line = str::from_utf8(&bytes).expect("utf8 command");
        let tag = first_word(line).to_owned();
        assert!(line.contains("SELECT INBOX"));

        expect_wants_read(&mut select, &mut frag);

        let reply = format!(
            "* FLAGS (\\Seen)\r\n\
             * 42 EXISTS\r\n\
             * 7 RECENT\r\n\
             * OK [UIDVALIDITY 1700] uid validity\r\n\
             * OK [NOMODSEQ] no modification sequences\r\n\
             {tag} OK [READ-WRITE] SELECT completed\r\n",
        );
        let data = expect_complete_ok(&mut select, &mut frag, reply.as_bytes()).data;
        assert_eq!(Some(42), data.exists);
        assert_eq!(Some(7), data.recent);
        assert_eq!(1700, data.uid_validity.expect("uid validity").get());
        assert_eq!(Some(false), data.read_only);
        assert!(data.no_mod_seq);
    }

    #[test]
    fn vanished_earlier_keeps_ranges() {
        let mut select = ImapMailboxSelect::new(
            "INBOX".try_into().expect("valid mailbox"),
            ImapMailboxSelectOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        expect_wants_tag(&mut select, &mut frag);
        let _ = expect_wants_write(&mut select, &mut frag, Some(b"A1"));
        expect_wants_read(&mut select, &mut frag);

        // NOTE: expanded, the first range would be four billion UIDs.
        let reply = b"* VANISHED (EARLIER) 1:4294967295\r\n\
                      * VANISHED (EARLIER) 9:3,12\r\n\
                      A1 OK [READ-WRITE] SELECT completed\r\n";
        let data = expect_complete_ok(&mut select, &mut frag, reply).data;

        let uid = |n| NonZeroU32::new(n).expect("non-zero");
        let expected = Vec::from([uid(1)..=NonZeroU32::MAX, uid(3)..=uid(9), uid(12)..=uid(12)]);
        assert_eq!(expected, data.vanished_earlier);
    }

    #[test]
    fn tagged_no_returns_no_error() {
        let mut select = ImapMailboxSelect::new(
            "INBOX".try_into().expect("valid mailbox"),
            ImapMailboxSelectOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        expect_wants_tag(&mut select, &mut frag);
        let bytes = expect_wants_write(&mut select, &mut frag, Some(b"A1"));
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read(&mut select, &mut frag);

        let reply = format!("{tag} NO mailbox does not exist\r\n");
        let err = expect_complete_err(&mut select, &mut frag, reply.as_bytes());
        let ImapMailboxSelectError::No(text) = err else {
            panic!("expected ImapMailboxSelectError::No, got {err:?}");
        };
        assert_eq!(text.text, "mailbox does not exist");
    }

    #[test]
    fn bye_returns_bye_error() {
        let mut select = ImapMailboxSelect::new(
            "INBOX".try_into().expect("valid mailbox"),
            ImapMailboxSelectOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        expect_wants_tag(&mut select, &mut frag);
        let _ = expect_wants_write(&mut select, &mut frag, Some(b"A1"));
        expect_wants_read(&mut select, &mut frag);

        let err = expect_complete_err(&mut select, &mut frag, b"* BYE going down\r\n");
        let ImapMailboxSelectError::Bye(text) = err else {
            panic!("expected ImapMailboxSelectError::Bye, got {err:?}");
        };
        assert_eq!(text, "going down");
    }

    fn expect_wants_tag(cor: &mut ImapMailboxSelect, frag: &mut Fragmentizer) {
        match cor.resume(frag, None) {
            ImapCoroutineState::Yielded(ImapYield::WantsTag) => {}
            state => panic!("expected WantsTag, got {state:?}"),
        }
    }

    fn expect_wants_write(
        cor: &mut ImapMailboxSelect,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> Vec<u8> {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ImapMailboxSelect, frag: &mut Fragmentizer) {
        match cor.resume(frag, None) {
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(
        cor: &mut ImapMailboxSelect,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> ImapOutput<ImapMailboxSelectData> {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Complete(Ok(value)) => value,
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut ImapMailboxSelect,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> ImapMailboxSelectError {
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
