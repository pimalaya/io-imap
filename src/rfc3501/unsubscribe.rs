//! I/O-free coroutine to send an IMAP UNSUBSCRIBE command (RFC 3501 §6.3.7).
//!
//! Removes a mailbox from the server's subscription list. No state is returned;
//! success is signalled by the tagged OK alone.

use core::fmt;

use alloc::string::{String, ToString};

use imap_codec::{
    CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        command::{Command, CommandBody},
        core::TagGenerator,
        mailbox::Mailbox,
        response::{StatusKind, Tagged},
    },
};
use log::trace;
use thiserror::Error;

use crate::{coroutine::*, imap_try, rfc3501::mailbox::encode_inplace, send::*};

/// Errors that can occur during UNSUBSCRIBE progression.
#[derive(Clone, Debug, Error)]
pub enum ImapMailboxUnsubscribeError {
    #[error("IMAP UNSUBSCRIBE failed: NO {0}")]
    No(String),
    #[error("IMAP UNSUBSCRIBE failed: BAD {0}")]
    Bad(String),
    #[error("IMAP UNSUBSCRIBE failed: BYE {0}")]
    Bye(String),

    #[error("IMAP UNSUBSCRIBE failed: server did not return a tagged response")]
    MissingTagged,

    #[error("IMAP UNSUBSCRIBE failed: {0}")]
    Send(#[from] SendImapCommandError),
}

/// I/O-free IMAP UNSUBSCRIBE coroutine.
pub struct ImapMailboxUnsubscribe {
    state: State,
}

impl ImapMailboxUnsubscribe {
    /// Creates a new UNSUBSCRIBE coroutine.
    pub fn new(mut mailbox: Mailbox<'static>) -> Self {
        encode_inplace(&mut mailbox);

        let command = Command {
            tag: TagGenerator::new().generate(),
            body: CommandBody::Unsubscribe { mailbox },
        };

        trace!("send IMAP command {command:?}");

        let state = State::Send(SendImapCommand::new(CommandCodec::new(), command));

        Self { state }
    }
}

impl ImapCoroutine for ImapMailboxUnsubscribe {
    type Yield = ImapYield;
    type Return = Result<(), ImapMailboxUnsubscribeError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        loop {
            trace!("unsubscribe: {}", self.state);

            match &mut self.state {
                State::Send(send) => {
                    let out = imap_try!(send, fragmentizer, arg);

                    if let Some(bye) = out.bye {
                        let err = ImapMailboxUnsubscribeError::Bye(bye.text.to_string());
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    let Some(Tagged { body, .. }) = out.tagged else {
                        let err = ImapMailboxUnsubscribeError::MissingTagged;
                        return ImapCoroutineState::Complete(Err(err));
                    };

                    return match body.kind {
                        StatusKind::Ok => ImapCoroutineState::Complete(Ok(())),
                        StatusKind::No => {
                            let err = ImapMailboxUnsubscribeError::No(body.text.to_string());
                            ImapCoroutineState::Complete(Err(err))
                        }
                        StatusKind::Bad => {
                            let err = ImapMailboxUnsubscribeError::Bad(body.text.to_string());
                            ImapCoroutineState::Complete(Err(err))
                        }
                    };
                }
            }
        }
    }
}

enum State {
    /// Send UNSUBSCRIBE and await the tagged response.
    Send(SendImapCommand<CommandCodec>),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(_) => f.write_str("send unsubscribe"),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::str;

    use alloc::{borrow::ToOwned, vec::Vec};

    use super::*;

    /// Happy path: tagged OK closes the command.
    #[test]
    fn success_returns_ok() {
        let mut unsub = ImapMailboxUnsubscribe::new("Archive".try_into().expect("valid mailbox"));
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut unsub, &mut frag, None);
        let line = str::from_utf8(&bytes).expect("utf8 command");
        let tag = first_word(line).to_owned();
        assert!(line.contains("UNSUBSCRIBE Archive"));

        expect_wants_read(&mut unsub, &mut frag);

        let reply = format!("{tag} OK UNSUBSCRIBE completed\r\n");
        expect_complete_ok(&mut unsub, &mut frag, reply.as_bytes());
    }

    /// Tagged NO: surface text verbatim.
    #[test]
    fn tagged_no_returns_no_error() {
        let mut unsub = ImapMailboxUnsubscribe::new("Archive".try_into().expect("valid mailbox"));
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut unsub, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read(&mut unsub, &mut frag);

        let reply = format!("{tag} NO not subscribed\r\n");
        let err = expect_complete_err(&mut unsub, &mut frag, reply.as_bytes());
        let ImapMailboxUnsubscribeError::No(text) = err else {
            panic!("expected ImapMailboxUnsubscribeError::No, got {err:?}");
        };
        assert_eq!(text, "not subscribed");
    }

    /// BYE before tagged response: surface text verbatim.
    #[test]
    fn bye_returns_bye_error() {
        let mut unsub = ImapMailboxUnsubscribe::new("Archive".try_into().expect("valid mailbox"));
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let _ = expect_wants_write(&mut unsub, &mut frag, None);
        expect_wants_read(&mut unsub, &mut frag);

        let err = expect_complete_err(&mut unsub, &mut frag, b"* BYE going down\r\n");
        let ImapMailboxUnsubscribeError::Bye(text) = err else {
            panic!("expected ImapMailboxUnsubscribeError::Bye, got {err:?}");
        };
        assert_eq!(text, "going down");
    }

    // --- utils

    fn expect_wants_write(
        cor: &mut ImapMailboxUnsubscribe,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> Vec<u8> {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ImapMailboxUnsubscribe, frag: &mut Fragmentizer) {
        match cor.resume(frag, None) {
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(cor: &mut ImapMailboxUnsubscribe, frag: &mut Fragmentizer, reply: &[u8]) {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Complete(Ok(())) => {}
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut ImapMailboxUnsubscribe,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> ImapMailboxUnsubscribeError {
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
