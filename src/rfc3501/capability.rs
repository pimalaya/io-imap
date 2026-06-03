//! IMAP CAPABILITY coroutine returning the advertised capability list.
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
//!     rfc3501::capability::ImapCapabilityGet,
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negociated, IMAP-authenticated)
//! let mut stream = TcpStream::connect("localhost:143").unwrap();
//!
//! let mut fragmentizer = Fragmentizer::new(50 * 1024 * 1024);
//! let mut buf = [0u8; 4096];
//!
//! let mut coroutine = ImapCapabilityGet::new();
//! let mut arg = None;
//!
//! let capability = loop {
//!     match coroutine.resume(&mut fragmentizer, arg.take()) {
//!         ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         ImapCoroutineState::Complete(Ok(capability)) => break capability,
//!         ImapCoroutineState::Complete(Err(err)) => panic!("{err}"),
//!     }
//! };
//!
//! println!("{capability:?}");
//! ```

use core::fmt;

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        command::{Command, CommandBody},
        core::TagGenerator,
        response::{Capability, Code, Data, StatusBody, StatusKind, Tagged},
    },
};
use log::trace;
use thiserror::Error;

use crate::{coroutine::*, imap_try, send::*};

/// Failure causes during the IMAP CAPABILITY flow.
#[derive(Clone, Debug, Error)]
pub enum ImapCapabilityGetError {
    #[error("IMAP CAPABILITY failed: NO {0}")]
    No(String),
    #[error("IMAP CAPABILITY failed: BAD {0}")]
    Bad(String),
    #[error("IMAP CAPABILITY failed: BYE {0}")]
    Bye(String),

    #[error("IMAP CAPABILITY failed: server did not return a tagged response")]
    MissingTagged,
    #[error("IMAP CAPABILITY failed: server did not advertise any capability")]
    MissingCapability,

    #[error("IMAP CAPABILITY failed: {0}")]
    Send(#[from] SendImapCommandError),
}

/// I/O-free IMAP CAPABILITY coroutine.
pub struct ImapCapabilityGet {
    state: State,
}

impl ImapCapabilityGet {
    pub fn new() -> Self {
        let command = Command {
            tag: TagGenerator::new().generate(),
            body: CommandBody::Capability,
        };

        trace!("send IMAP command {command:?}");

        let state = State::Send(SendImapCommand::new(CommandCodec::new(), command));

        Self { state }
    }
}

impl Default for ImapCapabilityGet {
    fn default() -> Self {
        Self::new()
    }
}

impl ImapCoroutine for ImapCapabilityGet {
    type Yield = ImapYield;
    type Return = Result<Vec<Capability<'static>>, ImapCapabilityGetError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        loop {
            trace!("capability: {}", self.state);

            match &mut self.state {
                State::Send(send) => {
                    let out = imap_try!(send, fragmentizer, arg);

                    if let Some(bye) = out.bye {
                        let err = ImapCapabilityGetError::Bye(bye.text.to_string());
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    let Some(Tagged { body, .. }) = out.tagged else {
                        let err = ImapCapabilityGetError::MissingTagged;
                        return ImapCoroutineState::Complete(Err(err));
                    };

                    let code = match body.kind {
                        StatusKind::Ok => body.code,
                        StatusKind::No => {
                            let err = ImapCapabilityGetError::No(body.text.to_string());
                            return ImapCoroutineState::Complete(Err(err));
                        }
                        StatusKind::Bad => {
                            let err = ImapCapabilityGetError::Bad(body.text.to_string());
                            return ImapCoroutineState::Complete(Err(err));
                        }
                    };

                    let mut new_capability = None;

                    if let Some(Code::Capability(capability)) = code {
                        new_capability.replace(capability);
                    }

                    for data in out.data {
                        if let Data::Capability(capability) = data {
                            new_capability.replace(capability);
                        }
                    }

                    for StatusBody { code, .. } in out.untagged {
                        if let Some(Code::Capability(capability)) = code {
                            new_capability.replace(capability);
                        }
                    }

                    let Some(capability) = new_capability else {
                        let err = ImapCapabilityGetError::MissingCapability;
                        return ImapCoroutineState::Complete(Err(err));
                    };

                    return ImapCoroutineState::Complete(Ok(capability.into_iter().collect()));
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
            Self::Send(_) => f.write_str("send capability"),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::str;

    use alloc::borrow::ToOwned;

    use super::*;

    #[test]
    fn data_capability_returns_capabilities() {
        let mut cap = ImapCapabilityGet::new();
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut cap, &mut frag, None);
        let line = str::from_utf8(&bytes).expect("utf8 command");
        let tag = first_word(line).to_owned();
        assert!(line.trim_end().ends_with("CAPABILITY"));

        expect_wants_read(&mut cap, &mut frag);

        let reply =
            format!("* CAPABILITY IMAP4REV1 STARTTLS IDLE\r\n{tag} OK CAPABILITY completed\r\n");
        let caps = expect_complete_ok(&mut cap, &mut frag, reply.as_bytes());
        assert_eq!(3, caps.len());
        assert!(caps.contains(&Capability::Imap4Rev1));
        assert!(caps.contains(&Capability::StartTls));
        assert!(caps.contains(&Capability::Idle));
    }

    #[test]
    fn tagged_code_capability_returns_capabilities() {
        let mut cap = ImapCapabilityGet::new();
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut cap, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read(&mut cap, &mut frag);

        let reply = format!("{tag} OK [CAPABILITY IMAP4REV1 IDLE] done\r\n");
        let caps = expect_complete_ok(&mut cap, &mut frag, reply.as_bytes());
        assert_eq!(2, caps.len());
    }

    #[test]
    fn no_capability_returns_missing_error() {
        let mut cap = ImapCapabilityGet::new();
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut cap, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read(&mut cap, &mut frag);

        let reply = format!("{tag} OK CAPABILITY completed\r\n");
        let err = expect_complete_err(&mut cap, &mut frag, reply.as_bytes());
        assert!(matches!(err, ImapCapabilityGetError::MissingCapability));
    }

    #[test]
    fn tagged_no_returns_no_error() {
        let mut cap = ImapCapabilityGet::new();
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut cap, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read(&mut cap, &mut frag);

        let reply = format!("{tag} NO server is sulking\r\n");
        let err = expect_complete_err(&mut cap, &mut frag, reply.as_bytes());
        let ImapCapabilityGetError::No(text) = err else {
            panic!("expected ImapCapabilityGetError::No, got {err:?}");
        };
        assert_eq!(text, "server is sulking");
    }

    #[test]
    fn bye_returns_bye_error() {
        let mut cap = ImapCapabilityGet::new();
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let _ = expect_wants_write(&mut cap, &mut frag, None);
        expect_wants_read(&mut cap, &mut frag);

        let err = expect_complete_err(&mut cap, &mut frag, b"* BYE going down\r\n");
        let ImapCapabilityGetError::Bye(text) = err else {
            panic!("expected ImapCapabilityGetError::Bye, got {err:?}");
        };
        assert_eq!(text, "going down");
    }

    // --- utils

    fn expect_wants_write(
        cor: &mut ImapCapabilityGet,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> Vec<u8> {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ImapCapabilityGet, frag: &mut Fragmentizer) {
        match cor.resume(frag, None) {
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(
        cor: &mut ImapCapabilityGet,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> Vec<Capability<'static>> {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Complete(Ok(value)) => value,
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut ImapCapabilityGet,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> ImapCapabilityGetError {
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
