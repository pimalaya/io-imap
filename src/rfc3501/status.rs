//! IMAP STATUS coroutine returning the requested status items.

use core::fmt;

use alloc::{borrow::Cow, string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        command::{Command, CommandBody},
        core::TagGenerator,
        mailbox::Mailbox,
        response::{Data, StatusKind, Tagged},
        status::{StatusDataItem, StatusDataItemName},
    },
};
use log::trace;
use thiserror::Error;

use crate::{coroutine::*, imap_try, rfc3501::mailbox::encode_inplace, send::*};

/// Failure causes during the IMAP STATUS flow.
#[derive(Clone, Debug, Error)]
pub enum ImapMailboxStatusError {
    #[error("IMAP STATUS failed: NO {0}")]
    No(String),
    #[error("IMAP STATUS failed: BAD {0}")]
    Bad(String),
    #[error("IMAP STATUS failed: BYE {0}")]
    Bye(String),

    #[error("IMAP STATUS failed: server did not return a tagged response")]
    MissingTagged,

    #[error("IMAP STATUS failed: {0}")]
    Send(#[from] SendImapCommandError),
}

/// I/O-free IMAP STATUS coroutine.
pub struct ImapMailboxStatus {
    state: State,
}

impl ImapMailboxStatus {
    pub fn new(
        mut mailbox: Mailbox<'static>,
        item_names: impl Into<Cow<'static, [StatusDataItemName]>>,
    ) -> Self {
        encode_inplace(&mut mailbox);

        let command = Command {
            tag: TagGenerator::new().generate(),
            body: CommandBody::Status {
                mailbox,
                item_names: item_names.into(),
            },
        };

        trace!("send IMAP command {command:?}");

        let state = State::Send(SendImapCommand::new(CommandCodec::new(), command));

        Self { state }
    }
}

impl ImapCoroutine for ImapMailboxStatus {
    type Yield = ImapYield;
    type Return = Result<Vec<StatusDataItem>, ImapMailboxStatusError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        loop {
            trace!("status: {}", self.state);

            match &mut self.state {
                State::Send(send) => {
                    let out = imap_try!(send, fragmentizer, arg);

                    if let Some(bye) = out.bye {
                        let err = ImapMailboxStatusError::Bye(bye.text.to_string());
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    let Some(Tagged { body, .. }) = out.tagged else {
                        let err = ImapMailboxStatusError::MissingTagged;
                        return ImapCoroutineState::Complete(Err(err));
                    };

                    let mut items = Vec::new();
                    for data in out.data {
                        if let Data::Status {
                            mailbox: _,
                            items: status_items,
                        } = data
                        {
                            items.extend(status_items.into_owned());
                        }
                    }

                    return match body.kind {
                        StatusKind::Ok => ImapCoroutineState::Complete(Ok(items)),
                        StatusKind::No => {
                            let err = ImapMailboxStatusError::No(body.text.to_string());
                            ImapCoroutineState::Complete(Err(err))
                        }
                        StatusKind::Bad => {
                            let err = ImapMailboxStatusError::Bad(body.text.to_string());
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
            Self::Send(_) => f.write_str("send status"),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::str;

    use alloc::{borrow::ToOwned, vec, vec::Vec};

    use super::*;

    fn items() -> Vec<StatusDataItemName> {
        vec![StatusDataItemName::Messages, StatusDataItemName::Recent]
    }

    #[test]
    fn success_returns_items() {
        let mut status =
            ImapMailboxStatus::new("INBOX".try_into().expect("valid mailbox"), items());
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut status, &mut frag, None);
        let line = str::from_utf8(&bytes).expect("utf8 command");
        let tag = first_word(line).to_owned();
        assert!(line.contains("STATUS INBOX"));

        expect_wants_read(&mut status, &mut frag);

        let reply =
            format!("* STATUS INBOX (MESSAGES 42 RECENT 3)\r\n{tag} OK STATUS completed\r\n");
        let out = expect_complete_ok(&mut status, &mut frag, reply.as_bytes());
        assert_eq!(2, out.len());
    }

    #[test]
    fn tagged_no_returns_no_error() {
        let mut status =
            ImapMailboxStatus::new("INBOX".try_into().expect("valid mailbox"), items());
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut status, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read(&mut status, &mut frag);

        let reply = format!("{tag} NO mailbox does not exist\r\n");
        let err = expect_complete_err(&mut status, &mut frag, reply.as_bytes());
        let ImapMailboxStatusError::No(text) = err else {
            panic!("expected ImapMailboxStatusError::No, got {err:?}");
        };
        assert_eq!(text, "mailbox does not exist");
    }

    #[test]
    fn bye_returns_bye_error() {
        let mut status =
            ImapMailboxStatus::new("INBOX".try_into().expect("valid mailbox"), items());
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let _ = expect_wants_write(&mut status, &mut frag, None);
        expect_wants_read(&mut status, &mut frag);

        let err = expect_complete_err(&mut status, &mut frag, b"* BYE going down\r\n");
        let ImapMailboxStatusError::Bye(text) = err else {
            panic!("expected ImapMailboxStatusError::Bye, got {err:?}");
        };
        assert_eq!(text, "going down");
    }

    // --- utils

    fn expect_wants_write(
        cor: &mut ImapMailboxStatus,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> Vec<u8> {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ImapMailboxStatus, frag: &mut Fragmentizer) {
        match cor.resume(frag, None) {
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(
        cor: &mut ImapMailboxStatus,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> Vec<StatusDataItem> {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Complete(Ok(value)) => value,
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut ImapMailboxStatus,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> ImapMailboxStatusError {
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
