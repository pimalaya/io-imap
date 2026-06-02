//! I/O-free coroutine to send an IMAP APPEND command (RFC 3501 §6.3.11).
//!
//! Reports the optional `EXISTS` count emitted by the server before the tagged
//! response, plus the `[APPENDUID uidvalidity uid]` response code defined by
//! UIDPLUS (RFC 4315) when the server announces it.

use core::fmt;

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        command::{Command, CommandBody},
        core::TagGenerator,
        datetime::DateTime,
        extensions::binary::LiteralOrLiteral8,
        flag::Flag,
        mailbox::Mailbox,
        response::{Code, Data, StatusKind, Tagged},
    },
};
use log::trace;
use thiserror::Error;

use crate::{coroutine::*, imap_try, rfc3501::mailbox::encode_inplace, send::*};

/// Output of the IMAP `APPEND` command: `EXISTS` count and `[APPENDUID
/// uidvalidity uid]` response code (RFC 4315) if the server returned either.
pub type ImapAppendOutput = (Option<u32>, Option<(u32, u32)>);

/// Errors that can occur during APPEND progression.
#[derive(Clone, Debug, Error)]
pub enum ImapMessageAppendError {
    #[error("IMAP APPEND failed: NO {0}")]
    No(String),
    #[error("IMAP APPEND failed: BAD {0}")]
    Bad(String),
    #[error("IMAP APPEND failed: BYE {0}")]
    Bye(String),

    #[error("IMAP APPEND failed: server did not return a tagged response")]
    MissingTagged,

    #[error("IMAP APPEND failed: {0}")]
    Send(#[from] SendImapCommandError),
}

/// Optional knobs for [`ImapMessageAppend::new`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImapMessageAppendOptions {
    /// Per-message flags attached on append. Default: empty (server applies no
    /// flags).
    pub flags: Vec<Flag<'static>>,
    /// Internal date stamp recorded by the server. Default: `None` (server uses
    /// its current time).
    pub date: Option<DateTime>,
}

/// I/O-free IMAP APPEND coroutine.
pub struct ImapMessageAppend {
    state: State,
}

impl ImapMessageAppend {
    /// Creates a new APPEND coroutine.
    pub fn new(
        mut mailbox: Mailbox<'static>,
        message: LiteralOrLiteral8<'static>,
        opts: ImapMessageAppendOptions,
    ) -> Self {
        encode_inplace(&mut mailbox);

        let command = Command {
            tag: TagGenerator::new().generate(),
            body: CommandBody::Append {
                mailbox,
                flags: opts.flags,
                date: opts.date,
                message,
            },
        };

        trace!("send IMAP command {command:?}");

        let state = State::Send(SendImapCommand::new(CommandCodec::new(), command));

        Self { state }
    }
}

impl ImapCoroutine for ImapMessageAppend {
    type Yield = ImapYield;
    type Return = Result<ImapAppendOutput, ImapMessageAppendError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        loop {
            trace!("append: {}", self.state);

            match &mut self.state {
                State::Send(send) => {
                    let out = imap_try!(send, fragmentizer, arg);

                    if let Some(bye) = out.bye {
                        let err = ImapMessageAppendError::Bye(bye.text.to_string());
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    let Some(Tagged { body, .. }) = out.tagged else {
                        let err = ImapMessageAppendError::MissingTagged;
                        return ImapCoroutineState::Complete(Err(err));
                    };

                    let mut exists = None;
                    for data in out.data {
                        if let Data::Exists(seq) = data {
                            exists = Some(seq);
                        }
                    }

                    return match body.kind {
                        StatusKind::Ok => {
                            let appenduid =
                                if let Some(Code::AppendUid { uid_validity, uid }) = body.code {
                                    Some((uid_validity.get(), uid.get()))
                                } else {
                                    None
                                };
                            ImapCoroutineState::Complete(Ok((exists, appenduid)))
                        }
                        StatusKind::No => {
                            let err = ImapMessageAppendError::No(body.text.to_string());
                            ImapCoroutineState::Complete(Err(err))
                        }
                        StatusKind::Bad => {
                            let err = ImapMessageAppendError::Bad(body.text.to_string());
                            ImapCoroutineState::Complete(Err(err))
                        }
                    };
                }
            }
        }
    }
}

enum State {
    /// Send APPEND (including the literal data) and await the tagged
    /// response.
    Send(SendImapCommand<CommandCodec>),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(_) => f.write_str("send append"),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::str;

    use alloc::borrow::ToOwned;

    use imap_codec::imap_types::core::Literal;

    use super::*;

    /// Happy path with non-sync literal: server returns tagged OK plus
    /// `[APPENDUID …]`. The coroutine surfaces both the EXISTS count
    /// and the APPENDUID pair.
    #[test]
    fn success_with_appenduid_returns_pair() {
        let message =
            LiteralOrLiteral8::Literal(Literal::unvalidated_non_sync(b"From: a@b\r\n\r\nhi"));
        let mut append = ImapMessageAppend::new(
            "INBOX".try_into().expect("valid mailbox"),
            message,
            ImapMessageAppendOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut append, &mut frag, None);
        let line = str::from_utf8(&bytes).expect("utf8 command");
        let tag = first_word(line).to_owned();
        assert!(line.contains("APPEND INBOX"));

        expect_wants_read(&mut append, &mut frag);

        let reply =
            format!("* 42 EXISTS\r\n{tag} OK [APPENDUID 1700000000 7] APPEND completed\r\n",);
        let (exists, appenduid) = expect_complete_ok(&mut append, &mut frag, reply.as_bytes());
        assert_eq!(Some(42), exists);
        assert_eq!(Some((1700000000, 7)), appenduid);
    }

    /// Server omits APPENDUID (UIDPLUS not advertised): the coroutine
    /// still succeeds with `appenduid = None`.
    #[test]
    fn success_without_appenduid_returns_none_uid() {
        let message = LiteralOrLiteral8::Literal(Literal::unvalidated_non_sync(b"x"));
        let mut append = ImapMessageAppend::new(
            "INBOX".try_into().expect("valid mailbox"),
            message,
            ImapMessageAppendOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut append, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read(&mut append, &mut frag);

        let reply = format!("{tag} OK APPEND completed\r\n");
        let (exists, appenduid) = expect_complete_ok(&mut append, &mut frag, reply.as_bytes());
        assert!(exists.is_none());
        assert!(appenduid.is_none());
    }

    /// Tagged NO: surface text verbatim.
    #[test]
    fn tagged_no_returns_no_error() {
        let message = LiteralOrLiteral8::Literal(Literal::unvalidated_non_sync(b"x"));
        let mut append = ImapMessageAppend::new(
            "INBOX".try_into().expect("valid mailbox"),
            message,
            ImapMessageAppendOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut append, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read(&mut append, &mut frag);

        let reply = format!("{tag} NO mailbox is read-only\r\n");
        let err = expect_complete_err(&mut append, &mut frag, reply.as_bytes());
        let ImapMessageAppendError::No(text) = err else {
            panic!("expected ImapMessageAppendError::No, got {err:?}");
        };
        assert_eq!(text, "mailbox is read-only");
    }

    /// Tagged BAD: surface text verbatim.
    #[test]
    fn tagged_bad_returns_bad_error() {
        let message = LiteralOrLiteral8::Literal(Literal::unvalidated_non_sync(b"x"));
        let mut append = ImapMessageAppend::new(
            "INBOX".try_into().expect("valid mailbox"),
            message,
            ImapMessageAppendOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut append, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read(&mut append, &mut frag);

        let reply = format!("{tag} BAD APPEND syntax error\r\n");
        let err = expect_complete_err(&mut append, &mut frag, reply.as_bytes());
        let ImapMessageAppendError::Bad(text) = err else {
            panic!("expected ImapMessageAppendError::Bad, got {err:?}");
        };
        assert_eq!(text, "APPEND syntax error");
    }

    /// BYE before tagged response: surface text verbatim.
    #[test]
    fn bye_returns_bye_error() {
        let message = LiteralOrLiteral8::Literal(Literal::unvalidated_non_sync(b"x"));
        let mut append = ImapMessageAppend::new(
            "INBOX".try_into().expect("valid mailbox"),
            message,
            ImapMessageAppendOptions::default(),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let _ = expect_wants_write(&mut append, &mut frag, None);
        expect_wants_read(&mut append, &mut frag);

        let err = expect_complete_err(&mut append, &mut frag, b"* BYE shutting down\r\n");
        let ImapMessageAppendError::Bye(text) = err else {
            panic!("expected ImapMessageAppendError::Bye, got {err:?}");
        };
        assert_eq!(text, "shutting down");
    }

    // --- utils

    fn expect_wants_write(
        cor: &mut ImapMessageAppend,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> Vec<u8> {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ImapMessageAppend, frag: &mut Fragmentizer) {
        match cor.resume(frag, None) {
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(
        cor: &mut ImapMessageAppend,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> ImapAppendOutput {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Complete(Ok(value)) => value,
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut ImapMessageAppend,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> ImapMessageAppendError {
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
