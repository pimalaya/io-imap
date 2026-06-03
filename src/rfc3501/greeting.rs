//! IMAP server greeting reader; optionally forces a CAPABILITY round-trip
//! if the greeting carries none.
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
//!     rfc3501::greeting::{ImapGreetingGet, ImapGreetingGetOptions},
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negociated)
//! let mut stream = TcpStream::connect("localhost:143").unwrap();
//!
//! let mut fragmentizer = Fragmentizer::new(50 * 1024 * 1024);
//! let mut buf = [0u8; 4096];
//!
//! let opts = ImapGreetingGetOptions {
//!     ensure_capabilities: true,
//! };
//! let mut coroutine = ImapGreetingGet::new(opts);
//! let mut arg = None;
//!
//! let greeting = loop {
//!     match coroutine.resume(&mut fragmentizer, arg.take()) {
//!         ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         ImapCoroutineState::Complete(Ok(greeting)) => break greeting,
//!         ImapCoroutineState::Complete(Err(err)) => panic!("{err}"),
//!     }
//! };
//!
//! println!("{greeting:?}");
//! ```

use core::{fmt, mem};

use alloc::{boxed::Box, string::String, string::ToString, vec::Vec};

use imap_codec::{
    GreetingCodec,
    fragmentizer::{DecodeMessageError, FragmentInfo, Fragmentizer},
    imap_types::{
        IntoStatic,
        response::{Capability, Code, GreetingKind},
        secret::Secret,
        utils::escape_byte_string,
    },
};
use log::trace;
use thiserror::Error;

use crate::{coroutine::*, imap_try, rfc3501::capability::*};

/// Failure causes while reading the IMAP greeting.
#[derive(Clone, Debug, Error)]
pub enum ImapGreetingGetError {
    #[error("IMAP greeting failed: BYE {0}")]
    Bye(String),

    #[error("IMAP greeting failed: reached unexpected EOF on stream")]
    Eof,
    #[error("IMAP greeting failed: decode error")]
    DecodingFailure(Secret<Box<[u8]>>),
    #[error("IMAP greeting failed: parse error: message is poisoned")]
    MessageIsPoisoned(Secret<Box<[u8]>>),
    #[error("IMAP greeting failed: parse error: message is too long")]
    MessageTooLong(Secret<Box<[u8]>>),

    #[error(transparent)]
    Capability(#[from] ImapCapabilityGetError),
}

/// Decoded greeting outcome.
#[derive(Debug)]
pub struct ImapGreetingOk {
    pub capability: Vec<Capability<'static>>,
    pub pre_authenticated: bool,
}

/// Options for [`ImapGreetingGet::new`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImapGreetingGetOptions {
    /// Fetch capabilities explicitly when the greeting carries none.
    pub ensure_capabilities: bool,
}

/// I/O-free IMAP greeting-read coroutine.
pub struct ImapGreetingGet {
    codec: GreetingCodec,
    state: State,
    wants_read: bool,
    observed: Vec<Capability<'static>>,
    pre_authenticated: bool,
    opts: ImapGreetingGetOptions,
}

impl ImapGreetingGet {
    pub fn new(opts: ImapGreetingGetOptions) -> Self {
        Self {
            codec: GreetingCodec::new(),
            state: State::Read,
            wants_read: false,
            observed: Vec::new(),
            pre_authenticated: false,
            opts,
        }
    }
}

impl ImapCoroutine for ImapGreetingGet {
    type Yield = ImapYield;
    type Return = Result<ImapGreetingOk, ImapGreetingGetError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        mut arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        loop {
            trace!("greeting: {}", self.state);

            if mem::take(&mut self.wants_read) {
                return ImapCoroutineState::Yielded(ImapYield::WantsRead);
            }

            match &mut self.state {
                State::Read => match arg.take() {
                    Some(&[]) => {
                        return ImapCoroutineState::Complete(Err(ImapGreetingGetError::Eof));
                    }
                    Some(bytes) => {
                        trace!("read bytes: {}", escape_byte_string(bytes));
                        fragmentizer.enqueue_bytes(bytes);
                        self.state = State::Deserialize;
                    }
                    None => {
                        self.wants_read = true;
                    }
                },
                State::Deserialize => match fragmentizer.progress() {
                    Some(info @ FragmentInfo::Line { .. }) => {
                        let bytes = fragmentizer.fragment_bytes(info);
                        trace!("read greeting line: {}", escape_byte_string(bytes));

                        if !fragmentizer.is_message_complete() {
                            continue;
                        }

                        match fragmentizer.decode_message(&self.codec) {
                            Ok(greeting) if greeting.kind == GreetingKind::Bye => {
                                let err = ImapGreetingGetError::Bye(greeting.text.to_string());
                                return ImapCoroutineState::Complete(Err(err));
                            }
                            Ok(greeting) => {
                                self.pre_authenticated = greeting.kind == GreetingKind::PreAuth;

                                if let Some(Code::Capability(capability)) = greeting.code {
                                    self.observed = capability.into_static().into_iter().collect();
                                }

                                if self.opts.ensure_capabilities && self.observed.is_empty() {
                                    self.state = State::Capability(ImapCapabilityGet::new());
                                    continue;
                                }

                                return ImapCoroutineState::Complete(Ok(ImapGreetingOk {
                                    capability: mem::take(&mut self.observed),
                                    pre_authenticated: self.pre_authenticated,
                                }));
                            }
                            Err(err) => {
                                let bytes = fragmentizer.message_bytes();
                                let bytes = Secret::new(bytes.into());
                                let err = match err {
                                    DecodeMessageError::DecodingFailure(_)
                                    | DecodeMessageError::DecodingRemainder { .. } => {
                                        ImapGreetingGetError::DecodingFailure(bytes)
                                    }
                                    DecodeMessageError::MessageTooLong { .. } => {
                                        ImapGreetingGetError::MessageTooLong(bytes)
                                    }
                                    DecodeMessageError::MessagePoisoned { .. } => {
                                        ImapGreetingGetError::MessageIsPoisoned(bytes)
                                    }
                                };
                                return ImapCoroutineState::Complete(Err(err));
                            }
                        }
                    }
                    // NOTE: greetings never carry literals.
                    Some(FragmentInfo::Literal { .. }) => unreachable!(),
                    None => {
                        self.state = State::Read;
                    }
                },
                State::Capability(capability) => {
                    let caps = imap_try!(capability, fragmentizer, arg.take());
                    return ImapCoroutineState::Complete(Ok(ImapGreetingOk {
                        capability: caps,
                        pre_authenticated: self.pre_authenticated,
                    }));
                }
            }
        }
    }
}

enum State {
    Read,
    Deserialize,
    Capability(ImapCapabilityGet),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read => f.write_str("read greeting"),
            Self::Deserialize => f.write_str("decode greeting"),
            Self::Capability(_) => f.write_str("fetch capabilities"),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    #[test]
    fn ok_with_inline_capability_returns_ok() {
        let mut greeting = ImapGreetingGet::new(ImapGreetingGetOptions {
            ensure_capabilities: true,
        });
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        expect_wants_read(&mut greeting, &mut frag);

        let reply = b"* OK [CAPABILITY IMAP4REV1 IDLE] hello\r\n";
        let ok = expect_complete_ok(&mut greeting, &mut frag, reply);
        assert!(!ok.pre_authenticated);
        assert_eq!(2, ok.capability.len());
    }

    #[test]
    fn ok_without_inline_capability_drives_extra_round_trip() {
        let mut greeting = ImapGreetingGet::new(ImapGreetingGetOptions {
            ensure_capabilities: true,
        });
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        expect_wants_read(&mut greeting, &mut frag);
        expect_wants_write_after(&mut greeting, &mut frag, b"* OK hello\r\n");
    }

    #[test]
    fn preauth_sets_flag() {
        let mut greeting = ImapGreetingGet::new(ImapGreetingGetOptions::default());
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        expect_wants_read(&mut greeting, &mut frag);

        let reply = b"* PREAUTH [CAPABILITY IMAP4REV1] welcome\r\n";
        let ok = expect_complete_ok(&mut greeting, &mut frag, reply);
        assert!(ok.pre_authenticated);
    }

    #[test]
    fn bye_returns_bye_error() {
        let mut greeting = ImapGreetingGet::new(ImapGreetingGetOptions::default());
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        expect_wants_read(&mut greeting, &mut frag);

        let err = expect_complete_err(&mut greeting, &mut frag, b"* BYE service unavailable\r\n");
        let ImapGreetingGetError::Bye(text) = err else {
            panic!("expected ImapGreetingGetError::Bye, got {err:?}");
        };
        assert_eq!(text, "service unavailable");
    }

    #[test]
    fn eof_returns_eof_error() {
        let mut greeting = ImapGreetingGet::new(ImapGreetingGetOptions::default());
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        expect_wants_read(&mut greeting, &mut frag);

        let err = expect_complete_err(&mut greeting, &mut frag, b"");
        assert!(matches!(err, ImapGreetingGetError::Eof));
    }

    // --- utils

    fn expect_wants_read(cor: &mut ImapGreetingGet, frag: &mut Fragmentizer) {
        match cor.resume(frag, None) {
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_wants_write_after(
        cor: &mut ImapGreetingGet,
        frag: &mut Fragmentizer,
        arg: &[u8],
    ) -> Vec<u8> {
        match cor.resume(frag, Some(arg)) {
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_complete_ok(
        cor: &mut ImapGreetingGet,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> ImapGreetingOk {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Complete(Ok(value)) => value,
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut ImapGreetingGet,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> ImapGreetingGetError {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        }
    }
}
