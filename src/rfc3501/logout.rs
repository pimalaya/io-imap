//! IMAP LOGOUT coroutine terminating the session.

use core::fmt;

use alloc::string::{String, ToString};

use imap_codec::{
    CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        command::{Command, CommandBody},
        core::TagGenerator,
        response::{StatusKind, Tagged},
    },
};
use log::trace;
use thiserror::Error;

use crate::{coroutine::*, imap_try, send::*};

/// Failure causes during the IMAP LOGOUT flow.
#[derive(Clone, Debug, Error)]
pub enum ImapLogoutError {
    #[error("IMAP LOGOUT failed: NO {0}")]
    No(String),
    #[error("IMAP LOGOUT failed: BAD {0}")]
    Bad(String),

    #[error("IMAP LOGOUT failed: server did not return a tagged response")]
    MissingTagged,
    #[error("IMAP LOGOUT failed: server did not send the expected BYE")]
    MissingBye,

    #[error("IMAP LOGOUT failed: {0}")]
    Send(#[from] SendImapCommandError),
}

/// I/O-free IMAP LOGOUT coroutine.
pub struct ImapLogout {
    state: State,
}

impl ImapLogout {
    pub fn new() -> Self {
        let command = Command {
            tag: TagGenerator::new().generate(),
            body: CommandBody::Logout,
        };

        trace!("send IMAP command {command:?}");

        let state = State::Send(SendImapCommand::new(CommandCodec::new(), command));

        Self { state }
    }
}

impl Default for ImapLogout {
    fn default() -> Self {
        Self::new()
    }
}

impl ImapCoroutine for ImapLogout {
    type Yield = ImapYield;
    type Return = Result<(), ImapLogoutError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        loop {
            trace!("logout: {}", self.state);

            match &mut self.state {
                State::Send(send) => {
                    let out = imap_try!(send, fragmentizer, arg);

                    if out.bye.is_none() {
                        return ImapCoroutineState::Complete(Err(ImapLogoutError::MissingBye));
                    }

                    let Some(Tagged { body, .. }) = out.tagged else {
                        return ImapCoroutineState::Complete(Err(ImapLogoutError::MissingTagged));
                    };

                    return match body.kind {
                        StatusKind::Ok => ImapCoroutineState::Complete(Ok(())),
                        StatusKind::No => {
                            let err = ImapLogoutError::No(body.text.to_string());
                            ImapCoroutineState::Complete(Err(err))
                        }
                        StatusKind::Bad => {
                            let err = ImapLogoutError::Bad(body.text.to_string());
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
            Self::Send(_) => f.write_str("send logout"),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::str;

    use alloc::{borrow::ToOwned, vec::Vec};

    use super::*;

    #[test]
    fn success_returns_ok() {
        let mut logout = ImapLogout::new();
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut logout, &mut frag, None);
        let line = str::from_utf8(&bytes).expect("utf8 command");
        let tag = first_word(line).to_owned();
        assert!(line.trim_end().ends_with("LOGOUT"));

        expect_wants_read(&mut logout, &mut frag);

        let reply = format!("* BYE bye\r\n{tag} OK LOGOUT completed\r\n");
        expect_complete_ok(&mut logout, &mut frag, reply.as_bytes());
    }

    #[test]
    fn missing_bye_returns_missing_bye_error() {
        let mut logout = ImapLogout::new();
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut logout, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read(&mut logout, &mut frag);

        let reply = format!("{tag} OK LOGOUT completed\r\n");
        let err = expect_complete_err(&mut logout, &mut frag, reply.as_bytes());
        assert!(matches!(err, ImapLogoutError::MissingBye));
    }

    #[test]
    fn tagged_bad_returns_bad_error() {
        let mut logout = ImapLogout::new();
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut logout, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read(&mut logout, &mut frag);

        let reply = format!("* BYE bye\r\n{tag} BAD LOGOUT not allowed\r\n");
        let err = expect_complete_err(&mut logout, &mut frag, reply.as_bytes());
        let ImapLogoutError::Bad(text) = err else {
            panic!("expected ImapLogoutError::Bad, got {err:?}");
        };
        assert_eq!(text, "LOGOUT not allowed");
    }

    // --- utils

    fn expect_wants_write(
        cor: &mut ImapLogout,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> Vec<u8> {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ImapLogout, frag: &mut Fragmentizer) {
        match cor.resume(frag, None) {
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(cor: &mut ImapLogout, frag: &mut Fragmentizer, reply: &[u8]) {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Complete(Ok(())) => {}
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut ImapLogout,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> ImapLogoutError {
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
