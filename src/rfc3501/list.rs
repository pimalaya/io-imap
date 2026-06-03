//! IMAP LIST coroutine returning matched mailbox rows.

use core::fmt;

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        command::{Command, CommandBody},
        core::{QuotedChar, TagGenerator},
        flag::FlagNameAttribute,
        mailbox::{ListMailbox, Mailbox},
        response::{Data, StatusKind, Tagged},
    },
};
use log::trace;
use thiserror::Error;

use crate::{
    coroutine::*,
    imap_try,
    rfc3501::mailbox::{decode_inplace, encode_inplace},
    send::*,
};

/// `(mailbox, hierarchy delimiter, attributes)` rows from LIST or LSUB.
pub type ImapMailboxListing = Vec<(
    Mailbox<'static>,
    Option<QuotedChar>,
    Vec<FlagNameAttribute<'static>>,
)>;

/// Failure causes during the IMAP LIST flow.
#[derive(Clone, Debug, Error)]
pub enum ImapMailboxListError {
    #[error("IMAP LIST failed: NO {0}")]
    No(String),
    #[error("IMAP LIST failed: BAD {0}")]
    Bad(String),
    #[error("IMAP LIST failed: BYE {0}")]
    Bye(String),

    #[error("IMAP LIST failed: server did not return a tagged response")]
    MissingTagged,

    #[error("IMAP LIST failed: {0}")]
    Send(#[from] SendImapCommandError),
}

/// I/O-free IMAP LIST coroutine.
pub struct ImapMailboxList {
    state: State,
}

impl ImapMailboxList {
    pub fn new(mut reference: Mailbox<'static>, mailbox_wildcard: ListMailbox<'static>) -> Self {
        encode_inplace(&mut reference);

        let command = Command {
            tag: TagGenerator::new().generate(),
            body: CommandBody::List {
                reference,
                mailbox_wildcard,
            },
        };

        trace!("send IMAP command {command:?}");

        let state = State::Send(SendImapCommand::new(CommandCodec::new(), command));

        Self { state }
    }
}

impl ImapCoroutine for ImapMailboxList {
    type Yield = ImapYield;
    type Return = Result<ImapMailboxListing, ImapMailboxListError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        loop {
            trace!("list: {}", self.state);

            match &mut self.state {
                State::Send(send) => {
                    let out = imap_try!(send, fragmentizer, arg);

                    if let Some(bye) = out.bye {
                        let err = ImapMailboxListError::Bye(bye.text.to_string());
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    let Some(Tagged { body, .. }) = out.tagged else {
                        let err = ImapMailboxListError::MissingTagged;
                        return ImapCoroutineState::Complete(Err(err));
                    };

                    let mut mailboxes = Vec::new();
                    for data in out.data {
                        if let Data::List {
                            items,
                            delimiter,
                            mailbox,
                        } = data
                        {
                            let mut mailbox = mailbox;
                            decode_inplace(&mut mailbox);
                            mailboxes.push((mailbox, delimiter, items));
                        }
                    }

                    return match body.kind {
                        StatusKind::Ok => ImapCoroutineState::Complete(Ok(mailboxes)),
                        StatusKind::No => {
                            let err = ImapMailboxListError::No(body.text.to_string());
                            ImapCoroutineState::Complete(Err(err))
                        }
                        StatusKind::Bad => {
                            let err = ImapMailboxListError::Bad(body.text.to_string());
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
            Self::Send(_) => f.write_str("send list"),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::str;

    use alloc::{borrow::ToOwned, vec::Vec};

    use super::*;

    #[test]
    fn success_returns_rows() {
        let reference: Mailbox = "".try_into().expect("valid reference");
        let pattern: ListMailbox = "*".try_into().expect("valid pattern");
        let mut list = ImapMailboxList::new(reference, pattern);
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut list, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read(&mut list, &mut frag);

        let reply = format!(
            "* LIST (\\HasNoChildren) \"/\" INBOX\r\n\
             * LIST (\\HasNoChildren) \"/\" Archive\r\n\
             {tag} OK LIST completed\r\n",
        );
        let rows = expect_complete_ok(&mut list, &mut frag, reply.as_bytes());
        assert_eq!(2, rows.len());
    }

    #[test]
    fn tagged_no_returns_no_error() {
        let mut list = ImapMailboxList::new(
            "".try_into().expect("valid reference"),
            "*".try_into().expect("valid pattern"),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut list, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read(&mut list, &mut frag);

        let reply = format!("{tag} NO not allowed\r\n");
        let err = expect_complete_err(&mut list, &mut frag, reply.as_bytes());
        let ImapMailboxListError::No(text) = err else {
            panic!("expected ImapMailboxListError::No, got {err:?}");
        };
        assert_eq!(text, "not allowed");
    }

    #[test]
    fn bye_returns_bye_error() {
        let mut list = ImapMailboxList::new(
            "".try_into().expect("valid reference"),
            "*".try_into().expect("valid pattern"),
        );
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let _ = expect_wants_write(&mut list, &mut frag, None);
        expect_wants_read(&mut list, &mut frag);

        let err = expect_complete_err(&mut list, &mut frag, b"* BYE going down\r\n");
        let ImapMailboxListError::Bye(text) = err else {
            panic!("expected ImapMailboxListError::Bye, got {err:?}");
        };
        assert_eq!(text, "going down");
    }

    // --- utils

    fn expect_wants_write(
        cor: &mut ImapMailboxList,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> Vec<u8> {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ImapMailboxList, frag: &mut Fragmentizer) {
        match cor.resume(frag, None) {
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(
        cor: &mut ImapMailboxList,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> ImapMailboxListing {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Complete(Ok(value)) => value,
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut ImapMailboxList,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> ImapMailboxListError {
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
