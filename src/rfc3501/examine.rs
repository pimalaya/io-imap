//! IMAP EXAMINE coroutine: read-only counterpart of SELECT.
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
//!     codec::fragmentizer::Fragmentizer,
//!     coroutine::{ImapCoroutine, ImapCoroutineState, ImapYield},
//!     rfc3501::examine::{ImapMailboxExamine, ImapMailboxExamineOptions},
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negotiated, IMAP-authenticated)
//! let mut stream = TcpStream::connect("localhost:143").unwrap();
//!
//! let mut fragmentizer = Fragmentizer::new(50 * 1024 * 1024);
//! let mut buf = [0u8; 4096];
//!
//! let mailbox = "INBOX".try_into().unwrap();
//! let opts = ImapMailboxExamineOptions::default();
//! let mut coroutine = ImapMailboxExamine::new(mailbox, opts);
//! let mut arg = None;
//!
//! let data = loop {
//!     match coroutine.resume(&mut fragmentizer, arg.take()) {
//!         ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         ImapCoroutineState::Complete(Ok(data)) => break data,
//!         ImapCoroutineState::Complete(Err(err)) => panic!("{err}"),
//!     }
//! };
//!
//! println!("{data:?}");
//! ```

use core::{fmt, num::NonZeroU32};

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        command::{Command, CommandBody, SelectParameter},
        core::TagGenerator,
        mailbox::Mailbox,
        response::{Code, Data, StatusBody, StatusKind, Tagged},
        sequence::SequenceSet,
    },
};
use log::trace;
use thiserror::Error;

use crate::{
    coroutine::*,
    imap_try,
    rfc3501::{
        mailbox::encode_inplace,
        select::{ImapMailboxSelectData, ImapMailboxSelectFetch},
    },
    send::*,
};

/// Decoded EXAMINE response (alias of [`ImapMailboxSelectData`]).
pub type ExamineData = ImapMailboxSelectData;
/// Implicit FETCH item from a QRESYNC EXAMINE (alias of
/// [`ImapMailboxSelectFetch`]).
pub type ExamineFetch = ImapMailboxSelectFetch;

/// Failure causes during the IMAP EXAMINE flow.
#[derive(Clone, Debug, Error)]
pub enum ImapMailboxExamineError {
    /// The server rejected the command with a NO response.
    #[error("IMAP EXAMINE failed: NO {0}")]
    No(String),
    /// The server rejected the command with a BAD response.
    #[error("IMAP EXAMINE failed: BAD {0}")]
    Bad(String),
    /// The server closed the session with an untagged BYE.
    #[error("IMAP EXAMINE failed: BYE {0}")]
    Bye(String),
    /// The exchange ended without a tagged response from the server.
    #[error("IMAP EXAMINE failed: server did not return a tagged response")]
    MissingTagged,
    /// The underlying send/receive exchange failed (EOF, decode, framing).
    #[error("IMAP EXAMINE failed: {0}")]
    Send(#[from] ImapSendError),
}

/// Options for [`ImapMailboxExamine::new`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImapMailboxExamineOptions {
    /// SELECT/EXAMINE parameters (RFC 4466), e.g. CONDSTORE/QRESYNC.
    pub parameters: Vec<SelectParameter>,
}

/// I/O-free IMAP EXAMINE coroutine.
pub struct ImapMailboxExamine {
    state: State,
}

impl ImapMailboxExamine {
    /// Builds an EXAMINE coroutine opening `mailbox` read-only;
    /// `opts.parameters` opts into CONDSTORE/QRESYNC extras.
    pub fn new(mut mailbox: Mailbox<'static>, opts: ImapMailboxExamineOptions) -> Self {
        encode_inplace(&mut mailbox);

        let command = Command {
            tag: TagGenerator::new().generate(),
            body: CommandBody::Examine {
                mailbox,
                parameters: opts.parameters,
            },
        };

        trace!("send IMAP command {command:?}");

        let state = State::Send(ImapSend::new(CommandCodec::new(), command));

        Self { state }
    }
}

impl ImapCoroutine for ImapMailboxExamine {
    type Yield = ImapYield;
    type Return = Result<ExamineData, ImapMailboxExamineError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        match &mut self.state {
            State::Send(send) => {
                let out = imap_try!(send, fragmentizer, arg);

                if let Some(bye) = out.bye {
                    let err = ImapMailboxExamineError::Bye(bye.text.to_string());
                    return ImapCoroutineState::Complete(Err(err));
                }

                let Some(Tagged { body, .. }) = out.tagged else {
                    let err = ImapMailboxExamineError::MissingTagged;
                    return ImapCoroutineState::Complete(Err(err));
                };

                let mut output = ExamineData::default();

                for data in out.data {
                    match data {
                        Data::Flags(flags) => output.flags = Some(flags),
                        Data::Exists(count) => output.exists = Some(count),
                        Data::Recent(count) => output.recent = Some(count),
                        Data::Fetch { seq, items } => {
                            output.changed.push(ExamineFetch { seq, items });
                        }
                        Data::Vanished {
                            earlier,
                            known_uids,
                        } if earlier => {
                            output.vanished_earlier.extend(expand_uid_set(&known_uids));
                        }
                        _ => {}
                    }
                }

                for StatusBody { kind, code, .. } in out.untagged {
                    if let StatusKind::Ok = kind {
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
                    StatusKind::Ok => ImapCoroutineState::Complete(Ok(output)),
                    StatusKind::No => {
                        let err = ImapMailboxExamineError::No(body.text.to_string());
                        ImapCoroutineState::Complete(Err(err))
                    }
                    StatusKind::Bad => {
                        let err = ImapMailboxExamineError::Bad(body.text.to_string());
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
            Self::Send(_) => f.write_str("send examine"),
        }
    }
}

/// Expand `VANISHED (EARLIER)` uid-set to concrete UIDs (RFC 7162 §3.2.10
/// forbids `*`, so `u32::MAX` is a safe ceiling).
fn expand_uid_set(uid_set: &SequenceSet) -> Vec<NonZeroU32> {
    let max = NonZeroU32::new(u32::MAX).unwrap();
    uid_set.iter(max).collect()
}

#[cfg(test)]
mod tests {
    use core::str;

    use alloc::{borrow::ToOwned, format};

    use crate::rfc3501::examine::*;

    #[test]
    fn success_collects_response() {
        let mut examine = ImapMailboxExamine::new(
            "INBOX".try_into().expect("valid mailbox"),
            ImapMailboxExamineOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut examine, &mut frag, None);
        let line = str::from_utf8(&bytes).expect("utf8 command");
        let tag = first_word(line).to_owned();
        assert!(line.contains("EXAMINE INBOX"));

        expect_wants_read(&mut examine, &mut frag);

        let reply = format!(
            "* FLAGS (\\Seen)\r\n\
             * 42 EXISTS\r\n\
             * 7 RECENT\r\n\
             * OK [UIDVALIDITY 1700] uid validity\r\n\
             {tag} OK [READ-ONLY] EXAMINE completed\r\n",
        );
        let data = expect_complete_ok(&mut examine, &mut frag, reply.as_bytes());
        assert_eq!(Some(42), data.exists);
        assert_eq!(Some(7), data.recent);
        assert_eq!(1700, data.uid_validity.expect("uid validity").get());
        assert!(data.flags.is_some());
    }

    #[test]
    fn tagged_no_returns_no_error() {
        let mut examine = ImapMailboxExamine::new(
            "INBOX".try_into().expect("valid mailbox"),
            ImapMailboxExamineOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut examine, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read(&mut examine, &mut frag);

        let reply = format!("{tag} NO mailbox does not exist\r\n");
        let err = expect_complete_err(&mut examine, &mut frag, reply.as_bytes());
        let ImapMailboxExamineError::No(text) = err else {
            panic!("expected ImapMailboxExamineError::No, got {err:?}");
        };
        assert_eq!(text, "mailbox does not exist");
    }

    #[test]
    fn tagged_bad_returns_bad_error() {
        let mut examine = ImapMailboxExamine::new(
            "INBOX".try_into().expect("valid mailbox"),
            ImapMailboxExamineOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut examine, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read(&mut examine, &mut frag);

        let reply = format!("{tag} BAD EXAMINE syntax error\r\n");
        let err = expect_complete_err(&mut examine, &mut frag, reply.as_bytes());
        let ImapMailboxExamineError::Bad(text) = err else {
            panic!("expected ImapMailboxExamineError::Bad, got {err:?}");
        };
        assert_eq!(text, "EXAMINE syntax error");
    }

    #[test]
    fn bye_returns_bye_error() {
        let mut examine = ImapMailboxExamine::new(
            "INBOX".try_into().expect("valid mailbox"),
            ImapMailboxExamineOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let _ = expect_wants_write(&mut examine, &mut frag, None);
        expect_wants_read(&mut examine, &mut frag);

        let err = expect_complete_err(&mut examine, &mut frag, b"* BYE going down\r\n");
        let ImapMailboxExamineError::Bye(text) = err else {
            panic!("expected ImapMailboxExamineError::Bye, got {err:?}");
        };
        assert_eq!(text, "going down");
    }

    fn expect_wants_write(
        cor: &mut ImapMailboxExamine,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> Vec<u8> {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ImapMailboxExamine, frag: &mut Fragmentizer) {
        match cor.resume(frag, None) {
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(
        cor: &mut ImapMailboxExamine,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> ExamineData {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Complete(Ok(value)) => value,
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut ImapMailboxExamine,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> ImapMailboxExamineError {
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
