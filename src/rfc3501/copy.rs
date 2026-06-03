//! IMAP COPY coroutine surfacing the optional COPYUID triple.

use core::fmt;

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        command::{Command, CommandBody},
        core::TagGenerator,
        extensions::uidplus::{UidElement, UidSet},
        mailbox::Mailbox,
        response::{Code, StatusKind, Tagged},
        sequence::SequenceSet,
    },
};
use log::trace;
use thiserror::Error;

use crate::{coroutine::*, imap_try, rfc3501::mailbox::encode_inplace, send::*};

/// `(uid_validity, source UIDs, destination UIDs)` from COPYUID.
pub type ImapCopyUid = Option<(u32, Vec<u32>, Vec<u32>)>;

/// Failure causes during the IMAP COPY flow.
#[derive(Clone, Debug, Error)]
pub enum ImapMessageCopyError {
    #[error("IMAP COPY failed: NO {0}")]
    No(String),
    #[error("IMAP COPY failed: BAD {0}")]
    Bad(String),
    #[error("IMAP COPY failed: BYE {0}")]
    Bye(String),

    #[error("IMAP COPY failed: server did not return a tagged response")]
    MissingTagged,

    #[error("IMAP COPY failed: {0}")]
    Send(#[from] SendImapCommandError),
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
    pub fn new(
        sequence_set: SequenceSet,
        mut mailbox: Mailbox<'static>,
        opts: ImapMessageCopyOptions,
    ) -> Self {
        encode_inplace(&mut mailbox);

        let command = Command {
            tag: TagGenerator::new().generate(),
            body: CommandBody::Copy {
                sequence_set,
                mailbox,
                uid: opts.uid,
            },
        };

        trace!("send IMAP command {command:?}");

        let state = State::Send(SendImapCommand::new(CommandCodec::new(), command));

        Self { state }
    }
}

impl ImapCoroutine for ImapMessageCopy {
    type Yield = ImapYield;
    type Return = Result<ImapCopyUid, ImapMessageCopyError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        loop {
            trace!("copy: {}", self.state);

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

                    return match body.kind {
                        StatusKind::Ok => {
                            let copyuid = if let Some(Code::CopyUid {
                                uid_validity,
                                source,
                                destination,
                            }) = body.code
                            {
                                Some((
                                    uid_validity.get(),
                                    uid_set_to_vec(source),
                                    uid_set_to_vec(destination),
                                ))
                            } else {
                                None
                            };
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
            Self::Send(_) => f.write_str("send copy"),
        }
    }
}

/// Expand a `UidSet` into a sorted `Vec<u32>`; shared with MOVE.
pub(crate) fn uid_set_to_vec(uid_set: UidSet) -> Vec<u32> {
    let mut uids = Vec::new();

    for elem in uid_set.0 {
        match elem {
            UidElement::Single(uid) => uids.push(uid.get()),
            UidElement::Range(start, end) => {
                let (lo, hi) = if start <= end {
                    (start.get(), end.get())
                } else {
                    (end.get(), start.get())
                };
                for uid in lo..=hi {
                    uids.push(uid);
                }
            }
        }
    }

    uids.sort_unstable();
    uids
}

#[cfg(test)]
mod tests {
    use core::str;

    use alloc::borrow::ToOwned;

    use super::*;

    #[test]
    fn success_with_copyuid_returns_uids() {
        let mut copy = ImapMessageCopy::new(
            "1:3".try_into().expect("valid sequence set"),
            "Archive".try_into().expect("valid mailbox"),
            ImapMessageCopyOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut copy, &mut frag, None);
        let line = str::from_utf8(&bytes).expect("utf8 command");
        let tag = first_word(line).to_owned();
        assert!(line.contains("COPY 1:3 Archive"));

        expect_wants_read(&mut copy, &mut frag);

        let reply = format!("{tag} OK [COPYUID 1700 1:3 10:12] COPY completed\r\n");
        let copyuid = expect_complete_ok(&mut copy, &mut frag, reply.as_bytes())
            .expect("server returned COPYUID");
        let (uid_validity, source, destination) = copyuid;
        assert_eq!(1700, uid_validity);
        assert_eq!(vec![1, 2, 3], source);
        assert_eq!(vec![10, 11, 12], destination);
    }

    #[test]
    fn uid_variant_sends_uid_copy() {
        let mut copy = ImapMessageCopy::new(
            "42".try_into().expect("valid sequence set"),
            "Archive".try_into().expect("valid mailbox"),
            ImapMessageCopyOptions { uid: true },
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut copy, &mut frag, None);
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

        let bytes = expect_wants_write(&mut copy, &mut frag, None);
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

        let bytes = expect_wants_write(&mut copy, &mut frag, None);
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

        let _ = expect_wants_write(&mut copy, &mut frag, None);
        expect_wants_read(&mut copy, &mut frag);

        let err = expect_complete_err(&mut copy, &mut frag, b"* BYE going down\r\n");
        let ImapMessageCopyError::Bye(text) = err else {
            panic!("expected ImapMessageCopyError::Bye, got {err:?}");
        };
        assert_eq!(text, "going down");
    }

    // --- utils

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
    ) -> ImapCopyUid {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Complete(Ok(value)) => value,
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
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
