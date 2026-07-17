//! IMAP MOVE coroutine surfacing the optional COPYUID triple.
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
//!     rfc6851::r#move::{ImapMessageMove, ImapMessageMoveOptions},
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
//! let opts = ImapMessageMoveOptions::default();
//! let mut coroutine = ImapMessageMove::new(sequence_set, mailbox, opts);
//! let mut arg = None;
//!
//! let copyuid = loop {
//!     match coroutine.resume(&mut fragmentizer, arg.take()) {
//!         ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
//!             stream.write_all(&bytes).unwrap();
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

/// Failure causes during the IMAP MOVE flow.
#[derive(Clone, Debug, Error)]
pub enum ImapMessageMoveError {
    /// The server rejected the MOVE command with a NO response.
    #[error("IMAP MOVE failed: NO {0}")]
    No(String),
    /// The server rejected the MOVE command with a BAD response.
    #[error("IMAP MOVE failed: BAD {0}")]
    Bad(String),
    /// The server closed the connection with a BYE response.
    #[error("IMAP MOVE failed: BYE {0}")]
    Bye(String),
    /// The server never answered with a tagged response.
    #[error("IMAP MOVE failed: server did not return a tagged response")]
    MissingTagged,
    /// The underlying send sub-coroutine failed.
    #[error("IMAP MOVE failed: {0}")]
    Send(#[from] ImapSendError),
}

/// Options for [`ImapMessageMove::new`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImapMessageMoveOptions {
    /// When `true`, send `UID MOVE` and treat `sequence_set` as UIDs.
    pub uid: bool,
}

/// I/O-free IMAP MOVE coroutine.
pub struct ImapMessageMove {
    state: State,
}

impl ImapMessageMove {
    /// Creates a coroutine that MOVEs the messages in `sequence_set`
    /// to `mailbox` and returns the COPYUID triple when present.
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

        let state = State::Send(ImapSend::new(CommandCodec::new(), command));

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

                match body.kind {
                    StatusKind::Ok => {
                        // NOTE: COPY carries COPYUID in the tagged OK
                        // (RFC 4315), but MOVE (RFC 6851 §4.4) emits it in an
                        // untagged OK before the EXPUNGE, so accept either
                        // placement, tagged first.
                        let copyuid = copyuid_from_code(body.code).or_else(|| {
                            out.untagged
                                .into_iter()
                                .find_map(|status| copyuid_from_code(status.code))
                        });
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
                }
            }
        }
    }
}

/// Extracts the `(uid_validity, source, destination)` COPYUID triple
/// from a response code, whether it rode the tagged or an untagged OK.
fn copyuid_from_code(code: Option<Code<'static>>) -> ImapCopyUid {
    match code {
        Some(Code::CopyUid {
            uid_validity,
            source,
            destination,
        }) => Some((
            uid_validity.get(),
            uid_set_to_vec(source),
            uid_set_to_vec(destination),
        )),
        _ => None,
    }
}

enum State {
    Send(ImapSend<CommandCodec>),
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

    use alloc::{borrow::ToOwned, format, vec, vec::Vec};

    use crate::rfc6851::r#move::*;

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

    #[test]
    fn success_with_untagged_copyuid_returns_uids() {
        // NOTE: RFC 6851 §4.4 (and Fastmail in practice): MOVE carries
        // COPYUID in an untagged OK before the EXPUNGE, not the tagged reply.
        let mut mov = ImapMessageMove::new(
            "1:3".try_into().expect("valid sequence set"),
            "Archive".try_into().expect("valid mailbox"),
            ImapMessageMoveOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut mov, &mut frag, None);
        let line = str::from_utf8(&bytes).expect("utf8 command");
        let tag = first_word(line).to_owned();

        expect_wants_read(&mut mov, &mut frag);

        let reply = format!(
            "* OK [COPYUID 1700 1:3 10:12] Completed\r\n\
             * 1 EXPUNGE\r\n\
             {tag} OK MOVE completed\r\n"
        );
        let copyuid = expect_complete_ok(&mut mov, &mut frag, reply.as_bytes())
            .expect("server returned untagged COPYUID");
        let (uid_validity, source, destination) = copyuid;
        assert_eq!(1700, uid_validity);
        assert_eq!(vec![1, 2, 3], source);
        assert_eq!(vec![10, 11, 12], destination);
    }

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
