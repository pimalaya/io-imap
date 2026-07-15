//! IMAP LOGIN coroutine; credentials travel in the clear, so the channel
//! must be TLS-protected.
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
//!     rfc3501::login::{ImapLogin, ImapLoginOptions},
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negotiated)
//! let mut stream = TcpStream::connect("localhost:143").unwrap();
//!
//! let mut fragmentizer = Fragmentizer::new(50 * 1024 * 1024);
//! let mut buf = [0u8; 4096];
//!
//! let opts = ImapLoginOptions::default();
//! let mut coroutine = ImapLogin::new("alice", "secret", opts).unwrap();
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

use core::{fmt, mem};

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use imap_codec::{
    CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        command::{Command, CommandBody},
        core::{IString, NString, TagGenerator},
        error::ValidationError,
        response::{Capability, Code, Data, StatusKind, Tagged},
        secret::Secret,
    },
};
use log::{debug, trace};
use thiserror::Error;

use crate::{coroutine::*, imap_try, rfc2971::id::*, rfc3501::capability::*, send::*};

/// Failure causes during the IMAP LOGIN flow.
#[derive(Clone, Debug, Error)]
pub enum ImapLoginError {
    /// The server rejected the command with a NO response.
    #[error("IMAP LOGIN failed: NO {0}")]
    No(String),
    /// The server rejected the command with a BAD response.
    #[error("IMAP LOGIN failed: BAD {0}")]
    Bad(String),
    /// The server closed the session with an untagged BYE.
    #[error("IMAP LOGIN failed: BYE {0}")]
    Bye(String),
    /// The exchange ended without a tagged response from the server.
    #[error("IMAP LOGIN failed: server did not return a tagged response")]
    MissingTagged,
    /// The underlying send/receive exchange failed (EOF, decode, framing).
    #[error("IMAP LOGIN failed: {0}")]
    Send(#[from] ImapSendError),
    /// The post-login CAPABILITY round-trip failed.
    #[error(transparent)]
    Capability(#[from] ImapCapabilityGetError),
    /// The post-login ID round-trip failed.
    #[error(transparent)]
    ServerId(#[from] ImapServerIdError),
}

/// Optional post-authentication round-trips.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImapLoginOptions {
    /// Fetch capabilities explicitly when the LOGIN response carries
    /// none. Defaults to skipping the extra round-trip.
    pub ensure_capabilities: bool,
    /// Send an ID command right after login with these parameters (an
    /// empty list sends `ID NIL`). Defaults to no ID round-trip.
    pub auto_id: Option<Vec<(IString<'static>, NString<'static>)>>,
}

/// I/O-free IMAP LOGIN coroutine.
pub struct ImapLogin {
    state: State,
    observed: Vec<Capability<'static>>,
    opts: ImapLoginOptions,
}

impl ImapLogin {
    /// Builds a LOGIN coroutine authenticating with `user` and
    /// `password`.
    ///
    /// Fails on credentials that cannot be encoded as IMAP AStrings
    /// (NUL, CR, LF).
    pub fn new(
        user: impl AsRef<str>,
        password: impl AsRef<str>,
        opts: ImapLoginOptions,
    ) -> Result<Self, ValidationError> {
        let username = user.as_ref().to_string().try_into()?;
        let password = Secret::new(password.as_ref().to_string().try_into()?);

        let cmd = Command {
            tag: TagGenerator::new().generate(),
            body: CommandBody::Login { username, password },
        };
        trace!("send IMAP command {cmd:?}");
        let send = ImapSend::new(CommandCodec::new(), cmd);

        Ok(Self {
            state: State::Send(send),
            observed: Vec::new(),
            opts,
        })
    }

    fn wants_capability(&mut self) -> Option<State> {
        (self.opts.ensure_capabilities && self.observed.is_empty())
            .then(|| State::Capability(ImapCapabilityGet::new()))
    }

    fn wants_id(&mut self) -> Option<State> {
        let params = self.opts.auto_id.take()?;
        let wire = (!params.is_empty()).then_some(params);
        Some(State::Id(ImapServerId::new(ImapServerIdOptions {
            parameters: wire,
        })))
    }
}

impl ImapCoroutine for ImapLogin {
    type Yield = ImapYield;
    type Return = Result<Vec<Capability<'static>>, ImapLoginError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        loop {
            match &mut self.state {
                State::Send(send) => {
                    let out = imap_try!(send, fragmentizer, arg);

                    if let Some(bye) = out.bye {
                        let err = ImapLoginError::Bye(bye.text.to_string());
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    let Some(Tagged { body, .. }) = out.tagged else {
                        let err = ImapLoginError::MissingTagged;
                        return ImapCoroutineState::Complete(Err(err));
                    };

                    let code = match body.kind {
                        StatusKind::Ok => body.code,
                        StatusKind::No => {
                            let err = ImapLoginError::No(body.text.to_string());
                            return ImapCoroutineState::Complete(Err(err));
                        }
                        StatusKind::Bad => {
                            let err = ImapLoginError::Bad(body.text.to_string());
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

                    if let Some(capability) = new_capability {
                        self.observed = capability.into_iter().collect();
                    }

                    if let Some(next) = self.wants_capability() {
                        self.state = next;
                        debug!("{}", self.state);
                        continue;
                    }

                    if let Some(next) = self.wants_id() {
                        self.state = next;
                        debug!("{}", self.state);
                        continue;
                    }

                    let capability = mem::take(&mut self.observed);
                    return ImapCoroutineState::Complete(Ok(capability));
                }
                State::Capability(capability) => {
                    self.observed = imap_try!(capability, fragmentizer, arg);

                    if let Some(next) = self.wants_id() {
                        self.state = next;
                        debug!("{}", self.state);
                        continue;
                    }

                    let capability = mem::take(&mut self.observed);
                    return ImapCoroutineState::Complete(Ok(capability));
                }
                State::Id(id) => {
                    imap_try!(id, fragmentizer, arg);
                    let capability = mem::take(&mut self.observed);
                    return ImapCoroutineState::Complete(Ok(capability));
                }
            }
        }
    }
}

enum State {
    Send(ImapSend<CommandCodec>),
    Capability(ImapCapabilityGet),
    Id(ImapServerId),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(_) => f.write_str("send login"),
            Self::Capability(_) => f.write_str("fetch capabilities"),
            Self::Id(_) => f.write_str("send id"),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::str;

    use alloc::format;

    use crate::rfc3501::login::*;

    #[test]
    fn success_returns_ok() {
        let opts = ImapLoginOptions::default();
        let mut auth = ImapLogin::new("alice", "secret", opts).expect("valid credentials");
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut auth, &mut frag, None);
        let line = str::from_utf8(&bytes).expect("utf8 command");
        let tag = first_word(line);
        assert!(line.contains("LOGIN "));

        expect_wants_read(&mut auth, &mut frag);

        let reply = format!("{tag} OK LOGIN completed\r\n");
        expect_complete_ok(&mut auth, &mut frag, reply.as_bytes());
    }

    #[test]
    fn invalid_credentials_returns_no_error() {
        let opts = ImapLoginOptions::default();
        let mut auth = ImapLogin::new("alice", "wrong", opts).expect("valid credentials");
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut auth, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command"));

        expect_wants_read(&mut auth, &mut frag);

        let reply = format!("{tag} NO authentication failed\r\n");
        let err = expect_complete_err(&mut auth, &mut frag, reply.as_bytes());
        let ImapLoginError::No(text) = err else {
            panic!("expected ImapLoginError::No, got {err:?}");
        };
        assert_eq!(text, "authentication failed");
    }

    #[test]
    fn tagged_bad_returns_bad_error() {
        let opts = ImapLoginOptions::default();
        let mut auth = ImapLogin::new("alice", "secret", opts).expect("valid credentials");
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut auth, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command"));

        expect_wants_read(&mut auth, &mut frag);

        let reply = format!("{tag} BAD LOGIN disabled\r\n");
        let err = expect_complete_err(&mut auth, &mut frag, reply.as_bytes());
        let ImapLoginError::Bad(text) = err else {
            panic!("expected ImapLoginError::Bad, got {err:?}");
        };
        assert_eq!(text, "LOGIN disabled");
    }

    #[test]
    fn success_with_capability_code_observes_capability() {
        let opts = ImapLoginOptions::default();
        let mut auth = ImapLogin::new("alice", "secret", opts).expect("valid credentials");
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut auth, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command"));

        expect_wants_read(&mut auth, &mut frag);

        let reply = format!("{tag} OK [CAPABILITY IMAP4rev1 IDLE] LOGIN completed\r\n");
        let caps = match auth.resume(&mut frag, Some(reply.as_bytes())) {
            ImapCoroutineState::Complete(Ok(caps)) => caps,
            state => panic!("expected Complete(Ok), got {state:?}"),
        };
        assert!(caps.iter().any(|c| matches!(c, Capability::Imap4Rev1)));
        assert!(caps.iter().any(|c| matches!(c, Capability::Idle)));
    }

    #[test]
    fn nul_in_password_fails_at_construction() {
        let opts = ImapLoginOptions::default();
        let result = ImapLogin::new("alice", "bad\0password", opts);
        assert!(
            result.is_err(),
            "expected construction to refuse NUL in password",
        );
    }

    fn expect_wants_write(
        cor: &mut ImapLogin,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> Vec<u8> {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ImapLogin, frag: &mut Fragmentizer) {
        match cor.resume(frag, None) {
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(cor: &mut ImapLogin, frag: &mut Fragmentizer, reply: &[u8]) {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Complete(Ok(_)) => {}
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut ImapLogin,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> ImapLoginError {
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
