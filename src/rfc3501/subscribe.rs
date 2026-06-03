//! I/O-free coroutine to send an IMAP SUBSCRIBE command (RFC 3501 §6.3.6).
//!
//! Adds a mailbox to the server's subscription list. No state is returned;
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

/// Errors that can occur during SUBSCRIBE progression.
#[derive(Clone, Debug, Error)]
pub enum ImapMailboxSubscribeError {
    #[error("IMAP SUBSCRIBE failed: NO {0}")]
    No(String),
    #[error("IMAP SUBSCRIBE failed: BAD {0}")]
    Bad(String),
    #[error("IMAP SUBSCRIBE failed: BYE {0}")]
    Bye(String),

    #[error("IMAP SUBSCRIBE failed: server did not return a tagged response")]
    MissingTagged,

    #[error("IMAP SUBSCRIBE failed: {0}")]
    Send(#[from] SendImapCommandError),
}

/// I/O-free IMAP SUBSCRIBE coroutine.
pub struct ImapMailboxSubscribe {
    state: State,
}

impl ImapMailboxSubscribe {
    /// Creates a new SUBSCRIBE coroutine.
    pub fn new(mut mailbox: Mailbox<'static>) -> Self {
        encode_inplace(&mut mailbox);

        let command = Command {
            tag: TagGenerator::new().generate(),
            body: CommandBody::Subscribe { mailbox },
        };

        trace!("send IMAP command {command:?}");

        let state = State::Send(SendImapCommand::new(CommandCodec::new(), command));

        Self { state }
    }
}

impl ImapCoroutine for ImapMailboxSubscribe {
    type Yield = ImapYield;
    type Return = Result<(), ImapMailboxSubscribeError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        loop {
            trace!("subscribe: {}", self.state);

            match &mut self.state {
                State::Send(send) => {
                    let out = imap_try!(send, fragmentizer, arg);

                    if let Some(bye) = out.bye {
                        let err = ImapMailboxSubscribeError::Bye(bye.text.to_string());
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    let Some(Tagged { body, .. }) = out.tagged else {
                        let err = ImapMailboxSubscribeError::MissingTagged;
                        return ImapCoroutineState::Complete(Err(err));
                    };

                    return match body.kind {
                        StatusKind::Ok => ImapCoroutineState::Complete(Ok(())),
                        StatusKind::No => {
                            let err = ImapMailboxSubscribeError::No(body.text.to_string());
                            ImapCoroutineState::Complete(Err(err))
                        }
                        StatusKind::Bad => {
                            let err = ImapMailboxSubscribeError::Bad(body.text.to_string());
                            ImapCoroutineState::Complete(Err(err))
                        }
                    };
                }
            }
        }
    }
}

enum State {
    /// Send SUBSCRIBE and await the tagged response.
    Send(SendImapCommand<CommandCodec>),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(_) => f.write_str("send subscribe"),
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
        let mut sub = ImapMailboxSubscribe::new("Archive".try_into().expect("valid mailbox"));
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut sub, &mut frag, None);
        let line = str::from_utf8(&bytes).expect("utf8 command");
        let tag = first_word(line).to_owned();
        assert!(line.contains("SUBSCRIBE Archive"));

        expect_wants_read(&mut sub, &mut frag);

        let reply = format!("{tag} OK SUBSCRIBE completed\r\n");
        expect_complete_ok(&mut sub, &mut frag, reply.as_bytes());
    }

    /// Tagged NO: surface text verbatim.
    #[test]
    fn tagged_no_returns_no_error() {
        let mut sub = ImapMailboxSubscribe::new("Archive".try_into().expect("valid mailbox"));
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut sub, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read(&mut sub, &mut frag);

        let reply = format!("{tag} NO mailbox does not exist\r\n");
        let err = expect_complete_err(&mut sub, &mut frag, reply.as_bytes());
        let ImapMailboxSubscribeError::No(text) = err else {
            panic!("expected ImapMailboxSubscribeError::No, got {err:?}");
        };
        assert_eq!(text, "mailbox does not exist");
    }

    /// BYE before tagged response: surface text verbatim.
    #[test]
    fn bye_returns_bye_error() {
        let mut sub = ImapMailboxSubscribe::new("Archive".try_into().expect("valid mailbox"));
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let _ = expect_wants_write(&mut sub, &mut frag, None);
        expect_wants_read(&mut sub, &mut frag);

        let err = expect_complete_err(&mut sub, &mut frag, b"* BYE going down\r\n");
        let ImapMailboxSubscribeError::Bye(text) = err else {
            panic!("expected ImapMailboxSubscribeError::Bye, got {err:?}");
        };
        assert_eq!(text, "going down");
    }

    // --- utils

    fn expect_wants_write(
        cor: &mut ImapMailboxSubscribe,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> Vec<u8> {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ImapMailboxSubscribe, frag: &mut Fragmentizer) {
        match cor.resume(frag, None) {
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(cor: &mut ImapMailboxSubscribe, frag: &mut Fragmentizer, reply: &[u8]) {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Complete(Ok(())) => {}
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut ImapMailboxSubscribe,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> ImapMailboxSubscribeError {
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
