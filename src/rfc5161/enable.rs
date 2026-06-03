//! IMAP ENABLE coroutine returning the server's ENABLED list.
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
//!     codec::{fragmentizer::Fragmentizer, imap_types::core::Vec1},
//!     coroutine::{ImapCoroutine, ImapCoroutineState, ImapYield},
//!     rfc5161::enable::ImapExtensionEnable,
//!     types::extensions::enable::CapabilityEnable,
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negociated, IMAP-authenticated)
//! let mut stream = TcpStream::connect("localhost:143").unwrap();
//!
//! let mut fragmentizer = Fragmentizer::new(50 * 1024 * 1024);
//! let mut buf = [0u8; 4096];
//!
//! let capabilities = Vec1::try_from(vec![CapabilityEnable::CondStore]).unwrap();
//! let mut coroutine = ImapExtensionEnable::new(capabilities);
//! let mut arg = None;
//!
//! let enabled = loop {
//!     match coroutine.resume(&mut fragmentizer, arg.take()) {
//!         ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         ImapCoroutineState::Complete(Ok(enabled)) => break enabled,
//!         ImapCoroutineState::Complete(Err(err)) => panic!("{err}"),
//!     }
//! };
//!
//! println!("{enabled:?}");
//! ```

use core::fmt;

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        command::{Command, CommandBody},
        core::{TagGenerator, Vec1},
        extensions::enable::CapabilityEnable,
        response::{Data, StatusKind, Tagged},
    },
};
use log::trace;
use thiserror::Error;

use crate::{coroutine::*, imap_try, send::*};

/// Failure causes during the IMAP ENABLE flow.
#[derive(Clone, Debug, Error)]
pub enum ImapExtensionEnableError {
    #[error("IMAP ENABLE failed: NO {0}")]
    No(String),
    #[error("IMAP ENABLE failed: BAD {0}")]
    Bad(String),
    #[error("IMAP ENABLE failed: BYE {0}")]
    Bye(String),

    #[error("IMAP ENABLE failed: server did not return a tagged response")]
    MissingTagged,

    #[error("IMAP ENABLE failed: {0}")]
    Send(#[from] SendImapCommandError),
}

/// I/O-free IMAP ENABLE coroutine.
pub struct ImapExtensionEnable {
    state: State,
}

impl ImapExtensionEnable {
    pub fn new(capabilities: Vec1<CapabilityEnable<'static>>) -> Self {
        let command = Command {
            tag: TagGenerator::new().generate(),
            body: CommandBody::Enable { capabilities },
        };

        trace!("send IMAP command {command:?}");

        let state = State::Send(SendImapCommand::new(CommandCodec::new(), command));

        Self { state }
    }
}

impl ImapCoroutine for ImapExtensionEnable {
    type Yield = ImapYield;
    type Return = Result<Option<Vec<CapabilityEnable<'static>>>, ImapExtensionEnableError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        loop {
            trace!("enable: {}", self.state);

            match &mut self.state {
                State::Send(send) => {
                    let out = imap_try!(send, fragmentizer, arg);

                    if let Some(bye) = out.bye {
                        let err = ImapExtensionEnableError::Bye(bye.text.to_string());
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    let Some(Tagged { body, .. }) = out.tagged else {
                        let err = ImapExtensionEnableError::MissingTagged;
                        return ImapCoroutineState::Complete(Err(err));
                    };

                    let mut enabled = None;
                    for data in out.data {
                        if let Data::Enabled { capabilities } = data {
                            enabled = Some(capabilities);
                        }
                    }

                    return match body.kind {
                        StatusKind::Ok => ImapCoroutineState::Complete(Ok(enabled)),
                        StatusKind::No => {
                            let err = ImapExtensionEnableError::No(body.text.to_string());
                            ImapCoroutineState::Complete(Err(err))
                        }
                        StatusKind::Bad => {
                            let err = ImapExtensionEnableError::Bad(body.text.to_string());
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
            Self::Send(_) => f.write_str("send enable"),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::str;

    use alloc::{borrow::ToOwned, vec, vec::Vec};

    use super::*;

    fn caps() -> Vec1<CapabilityEnable<'static>> {
        Vec1::try_from(vec![CapabilityEnable::CondStore]).expect("one cap")
    }

    #[test]
    fn success_returns_enabled_list() {
        let mut enable = ImapExtensionEnable::new(caps());
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut enable, &mut frag, None);
        let line = str::from_utf8(&bytes).expect("utf8 command");
        let tag = first_word(line).to_owned();
        assert!(line.contains("ENABLE CONDSTORE"));

        expect_wants_read(&mut enable, &mut frag);

        let reply = format!("* ENABLED CONDSTORE\r\n{tag} OK ENABLE completed\r\n");
        let enabled = expect_complete_ok(&mut enable, &mut frag, reply.as_bytes())
            .expect("server returned ENABLED");
        assert_eq!(1, enabled.len());
    }

    #[test]
    fn success_without_enabled_returns_none() {
        let mut enable = ImapExtensionEnable::new(caps());
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut enable, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read(&mut enable, &mut frag);

        let reply = format!("{tag} OK ENABLE completed\r\n");
        let enabled = expect_complete_ok(&mut enable, &mut frag, reply.as_bytes());
        assert!(enabled.is_none());
    }

    #[test]
    fn tagged_no_returns_no_error() {
        let mut enable = ImapExtensionEnable::new(caps());
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut enable, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read(&mut enable, &mut frag);

        let reply = format!("{tag} NO CONDSTORE not supported\r\n");
        let err = expect_complete_err(&mut enable, &mut frag, reply.as_bytes());
        let ImapExtensionEnableError::No(text) = err else {
            panic!("expected ImapExtensionEnableError::No, got {err:?}");
        };
        assert_eq!(text, "CONDSTORE not supported");
    }

    #[test]
    fn bye_returns_bye_error() {
        let mut enable = ImapExtensionEnable::new(caps());
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let _ = expect_wants_write(&mut enable, &mut frag, None);
        expect_wants_read(&mut enable, &mut frag);

        let err = expect_complete_err(&mut enable, &mut frag, b"* BYE going down\r\n");
        let ImapExtensionEnableError::Bye(text) = err else {
            panic!("expected ImapExtensionEnableError::Bye, got {err:?}");
        };
        assert_eq!(text, "going down");
    }

    // --- utils

    fn expect_wants_write(
        cor: &mut ImapExtensionEnable,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> Vec<u8> {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ImapExtensionEnable, frag: &mut Fragmentizer) {
        match cor.resume(frag, None) {
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(
        cor: &mut ImapExtensionEnable,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> Option<Vec<CapabilityEnable<'static>>> {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Complete(Ok(value)) => value,
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut ImapExtensionEnable,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> ImapExtensionEnableError {
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
