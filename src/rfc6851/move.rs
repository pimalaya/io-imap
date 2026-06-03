//! I/O-free coroutine to send an IMAP MOVE command (RFC 6851), optionally as
//! the `UID MOVE` variant.
//!
//! Surfaces the `[COPYUID uidvalidity src-uids dst-uids]` response code defined
//! by UIDPLUS (RFC 4315) when the server announces it, decoded the same way as
//! [`crate::rfc3501::copy::ImapMessageCopy`].

use core::fmt;

use alloc::string::{String, ToString};

use imap_codec::{
    CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        command::{Command, CommandBody},
        core::TagGenerator,
        mailbox::Mailbox,
        response::{Code, StatusKind, Tagged},
        sequence::SequenceSet,
    },
};
use log::trace;
use thiserror::Error;

use crate::{
    coroutine::*,
    imap_try,
    rfc3501::{
        copy::{ImapCopyUid, uid_set_to_vec},
        mailbox::encode_inplace,
    },
    send::*,
};

/// Errors that can occur during MOVE progression.
#[derive(Clone, Debug, Error)]
pub enum ImapMessageMoveError {
    #[error("IMAP MOVE failed: NO {0}")]
    No(String),
    #[error("IMAP MOVE failed: BAD {0}")]
    Bad(String),
    #[error("IMAP MOVE failed: BYE {0}")]
    Bye(String),

    #[error("IMAP MOVE failed: server did not return a tagged response")]
    MissingTagged,

    #[error("IMAP MOVE failed: {0}")]
    Send(#[from] SendImapCommandError),
}

/// Options for [`ImapMessageMove::new`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImapMessageMoveOptions {
    /// When `true`, send `UID MOVE`; the `sequence_set` then holds
    /// UIDs rather than sequence numbers. Default: `false`.
    pub uid: bool,
}

/// I/O-free IMAP MOVE coroutine.
pub struct ImapMessageMove {
    state: State,
}

impl ImapMessageMove {
    /// Creates a new MOVE coroutine.
    pub fn new(
        sequence_set: SequenceSet,
        mut mailbox: Mailbox<'static>,
        opts: ImapMessageMoveOptions,
    ) -> Self {
        encode_inplace(&mut mailbox);

        let command = Command {
            tag: TagGenerator::new().generate(),
            body: CommandBody::Move {
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

impl ImapCoroutine for ImapMessageMove {
    type Yield = ImapYield;
    type Return = Result<ImapCopyUid, ImapMessageMoveError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        loop {
            trace!("move: {}", self.state);

            match &mut self.state {
                State::Send(send) => {
                    let out = imap_try!(send, fragmentizer, arg);

                    if let Some(bye) = out.bye {
                        let err = ImapMessageMoveError::Bye(bye.text.to_string());
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    let Some(Tagged { body, .. }) = out.tagged else {
                        let err = ImapMessageMoveError::MissingTagged;
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
                            let err = ImapMessageMoveError::No(body.text.to_string());
                            ImapCoroutineState::Complete(Err(err))
                        }
                        StatusKind::Bad => {
                            let err = ImapMessageMoveError::Bad(body.text.to_string());
                            ImapCoroutineState::Complete(Err(err))
                        }
                    };
                }
            }
        }
    }
}

enum State {
    /// Send MOVE (or UID MOVE) and await the tagged response.
    Send(SendImapCommand<CommandCodec>),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(_) => f.write_str("send move"),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::str;

    use alloc::{borrow::ToOwned, vec, vec::Vec};

    use super::*;

    /// Happy path with COPYUID: server returns the `[COPYUID …]`
    /// code; the coroutine decodes source/destination.
    #[test]
    fn success_with_copyuid_returns_uids() {
        let mut mov = ImapMessageMove::new(
            "1:3".try_into().expect("valid sequence set"),
            "Archive".try_into().expect("valid mailbox"),
            ImapMessageMoveOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut mov, &mut frag, None);
        let line = str::from_utf8(&bytes).expect("utf8 command");
        let tag = first_word(line).to_owned();
        assert!(line.contains("MOVE 1:3 Archive"));

        expect_wants_read(&mut mov, &mut frag);

        let reply = format!("{tag} OK [COPYUID 1700 1:3 10:12] MOVE completed\r\n");
        let copyuid = expect_complete_ok(&mut mov, &mut frag, reply.as_bytes())
            .expect("server returned COPYUID");
        let (uid_validity, source, destination) = copyuid;
        assert_eq!(1700, uid_validity);
        assert_eq!(vec![1, 2, 3], source);
        assert_eq!(vec![10, 11, 12], destination);
    }

    /// UID flag flips the wire keyword to `UID MOVE`.
    #[test]
    fn uid_variant_sends_uid_move() {
        let mut mov = ImapMessageMove::new(
            "42".try_into().expect("valid sequence set"),
            "Archive".try_into().expect("valid mailbox"),
            ImapMessageMoveOptions { uid: true },
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut mov, &mut frag, None);
        let line = str::from_utf8(&bytes).expect("utf8 command");
        assert!(line.contains("UID MOVE 42 Archive"));
    }

    /// Tagged NO: surface text verbatim.
    #[test]
    fn tagged_no_returns_no_error() {
        let mut mov = ImapMessageMove::new(
            "1".try_into().expect("valid sequence set"),
            "Archive".try_into().expect("valid mailbox"),
            ImapMessageMoveOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut mov, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read(&mut mov, &mut frag);

        let reply = format!("{tag} NO destination mailbox does not exist\r\n");
        let err = expect_complete_err(&mut mov, &mut frag, reply.as_bytes());
        let ImapMessageMoveError::No(text) = err else {
            panic!("expected ImapMessageMoveError::No, got {err:?}");
        };
        assert_eq!(text, "destination mailbox does not exist");
    }

    /// BYE before tagged response: surface text verbatim.
    #[test]
    fn bye_returns_bye_error() {
        let mut mov = ImapMessageMove::new(
            "1".try_into().expect("valid sequence set"),
            "Archive".try_into().expect("valid mailbox"),
            ImapMessageMoveOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let _ = expect_wants_write(&mut mov, &mut frag, None);
        expect_wants_read(&mut mov, &mut frag);

        let err = expect_complete_err(&mut mov, &mut frag, b"* BYE going down\r\n");
        let ImapMessageMoveError::Bye(text) = err else {
            panic!("expected ImapMessageMoveError::Bye, got {err:?}");
        };
        assert_eq!(text, "going down");
    }

    // --- utils

    fn expect_wants_write(
        cor: &mut ImapMessageMove,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> Vec<u8> {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ImapMessageMove, frag: &mut Fragmentizer) {
        match cor.resume(frag, None) {
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(
        cor: &mut ImapMessageMove,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> ImapCopyUid {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Complete(Ok(value)) => value,
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut ImapMessageMove,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> ImapMessageMoveError {
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
