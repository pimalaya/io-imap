//! IMAP SELECT coroutine; accepts SELECT parameters (RFC 4466) to opt
//! into CONDSTORE/QRESYNC extras.

use core::{fmt, num::NonZeroU32};

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        command::{Command, CommandBody, SelectParameter},
        core::{TagGenerator, Vec1},
        fetch::MessageDataItem,
        flag::{Flag, FlagPerm},
        mailbox::Mailbox,
        response::{Code, Data, StatusBody, StatusKind, Tagged},
        sequence::SequenceSet,
    },
};
use log::trace;
use thiserror::Error;

use crate::{coroutine::*, imap_try, rfc3501::mailbox::encode_inplace, send::*};

/// Failure causes during the IMAP SELECT flow.
#[derive(Clone, Debug, Error)]
pub enum ImapMailboxSelectError {
    #[error("IMAP SELECT failed: NO {0}")]
    No(String),
    #[error("IMAP SELECT failed: BAD {0}")]
    Bad(String),
    #[error("IMAP SELECT failed: BYE {0}")]
    Bye(String),

    #[error("IMAP SELECT failed: server did not return a tagged response")]
    MissingTagged,

    #[error("IMAP SELECT failed: {0}")]
    Send(#[from] SendImapCommandError),
}

/// Decoded SELECT (or EXAMINE) response. CONDSTORE/QRESYNC extras
/// (`highest_mod_seq`, `vanished_earlier`, `changed`) stay empty on the
/// base call.
#[derive(Clone, Debug, Default)]
pub struct SelectData {
    pub flags: Option<Vec<Flag<'static>>>,
    pub exists: Option<u32>,
    pub recent: Option<u32>,
    pub unseen: Option<NonZeroU32>,
    pub permanent_flags: Option<Vec<FlagPerm<'static>>>,
    pub uid_next: Option<NonZeroU32>,
    pub uid_validity: Option<NonZeroU32>,
    pub highest_mod_seq: Option<u64>,
    pub vanished_earlier: Vec<NonZeroU32>,
    pub changed: Vec<SelectFetch>,
}

/// Implicit FETCH returned during a QRESYNC SELECT.
#[derive(Clone, Debug)]
pub struct SelectFetch {
    pub seq: NonZeroU32,
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
    pub fn new(mut mailbox: Mailbox<'static>, opts: ImapMailboxSelectOptions) -> Self {
        encode_inplace(&mut mailbox);

        let command = Command {
            tag: TagGenerator::new().generate(),
            body: CommandBody::Select {
                mailbox,
                parameters: opts.parameters,
            },
        };

        trace!("send IMAP command {command:?}");

        let state = State::Send(SendImapCommand::new(CommandCodec::new(), command));

        Self { state }
    }
}

impl ImapCoroutine for ImapMailboxSelect {
    type Yield = ImapYield;
    type Return = Result<SelectData, ImapMailboxSelectError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        loop {
            trace!("select: {}", self.state);

            match &mut self.state {
                State::Send(send) => {
                    let out = imap_try!(send, fragmentizer, arg);

                    if let Some(bye) = out.bye {
                        let err = ImapMailboxSelectError::Bye(bye.text.to_string());
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    let Some(Tagged { body, .. }) = out.tagged else {
                        let err = ImapMailboxSelectError::MissingTagged;
                        return ImapCoroutineState::Complete(Err(err));
                    };

                    let mut output = SelectData::default();

                    for data in out.data {
                        match data {
                            Data::Flags(flags) => output.flags = Some(flags),
                            Data::Exists(count) => output.exists = Some(count),
                            Data::Recent(count) => output.recent = Some(count),
                            Data::Fetch { seq, items } => {
                                output.changed.push(SelectFetch { seq, items });
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

                    return match body.kind {
                        StatusKind::Ok => ImapCoroutineState::Complete(Ok(output)),
                        StatusKind::No => {
                            let err = ImapMailboxSelectError::No(body.text.to_string());
                            ImapCoroutineState::Complete(Err(err))
                        }
                        StatusKind::Bad => {
                            let err = ImapMailboxSelectError::Bad(body.text.to_string());
                            ImapCoroutineState::Complete(Err(err))
                        }
                    };
                }
            }
        }
    }
}

enum State {
    Send(SendImapCommand<CommandCodec>),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(_) => f.write_str("send select"),
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

    use alloc::{borrow::ToOwned, vec::Vec};

    use super::*;

    #[test]
    fn success_collects_response() {
        let mut select = ImapMailboxSelect::new(
            "INBOX".try_into().expect("valid mailbox"),
            ImapMailboxSelectOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut select, &mut frag, None);
        let line = str::from_utf8(&bytes).expect("utf8 command");
        let tag = first_word(line).to_owned();
        assert!(line.contains("SELECT INBOX"));

        expect_wants_read(&mut select, &mut frag);

        let reply = format!(
            "* FLAGS (\\Seen)\r\n\
             * 42 EXISTS\r\n\
             * 7 RECENT\r\n\
             * OK [UIDVALIDITY 1700] uid validity\r\n\
             {tag} OK [READ-WRITE] SELECT completed\r\n",
        );
        let data = expect_complete_ok(&mut select, &mut frag, reply.as_bytes());
        assert_eq!(Some(42), data.exists);
        assert_eq!(Some(7), data.recent);
        assert_eq!(1700, data.uid_validity.expect("uid validity").get());
    }

    #[test]
    fn tagged_no_returns_no_error() {
        let mut select = ImapMailboxSelect::new(
            "INBOX".try_into().expect("valid mailbox"),
            ImapMailboxSelectOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut select, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read(&mut select, &mut frag);

        let reply = format!("{tag} NO mailbox does not exist\r\n");
        let err = expect_complete_err(&mut select, &mut frag, reply.as_bytes());
        let ImapMailboxSelectError::No(text) = err else {
            panic!("expected ImapMailboxSelectError::No, got {err:?}");
        };
        assert_eq!(text, "mailbox does not exist");
    }

    #[test]
    fn bye_returns_bye_error() {
        let mut select = ImapMailboxSelect::new(
            "INBOX".try_into().expect("valid mailbox"),
            ImapMailboxSelectOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let _ = expect_wants_write(&mut select, &mut frag, None);
        expect_wants_read(&mut select, &mut frag);

        let err = expect_complete_err(&mut select, &mut frag, b"* BYE going down\r\n");
        let ImapMailboxSelectError::Bye(text) = err else {
            panic!("expected ImapMailboxSelectError::Bye, got {err:?}");
        };
        assert_eq!(text, "going down");
    }

    // --- utils

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
    ) -> SelectData {
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
