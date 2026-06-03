//! IMAP IDLE coroutine yielding mailbox change events.
//!
//! # Example
//!
//! ```rust,no_run
//! use core::sync::atomic::AtomicBool;
//! use std::{
//!     io::{Read, Write},
//!     net::TcpStream,
//!     sync::Arc,
//! };
//!
//! use io_imap::{
//!     codec::fragmentizer::Fragmentizer,
//!     coroutine::{ImapCoroutine, ImapCoroutineState},
//!     rfc2177::idle::{ImapIdle, ImapIdleOptions, ImapIdleYield},
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negociated, IMAP-authenticated)
//! let mut stream = TcpStream::connect("localhost:143").unwrap();
//!
//! let mut fragmentizer = Fragmentizer::new(50 * 1024 * 1024);
//! let mut buf = [0u8; 4096];
//!
//! let shutdown = Arc::new(AtomicBool::new(false));
//! let mut coroutine = ImapIdle::new(shutdown.clone(), ImapIdleOptions::default());
//! let mut arg = None;
//!
//! loop {
//!     match coroutine.resume(&mut fragmentizer, arg.take()) {
//!         ImapCoroutineState::Yielded(ImapIdleYield::WantsWrite(bytes)) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         ImapCoroutineState::Yielded(ImapIdleYield::WantsRead) => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         ImapCoroutineState::Yielded(ImapIdleYield::Event(event)) => {
//!             println!("{event:?}");
//!         }
//!         ImapCoroutineState::Complete(Ok(())) => break,
//!         ImapCoroutineState::Complete(Err(err)) => panic!("{err}"),
//!     }
//! }
//! ```

use core::{
    fmt, mem,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use alloc::{boxed::Box, string::String, string::ToString, sync::Arc, vec::Vec};

#[cfg(feature = "client")]
use std::time::Instant;

use imap_codec::{
    CommandCodec, IdleDoneCodec, ResponseCodec,
    fragmentizer::{DecodeMessageError, FragmentInfo, Fragmentizer},
    imap_types::{
        IntoStatic,
        command::{Command, CommandBody},
        core::TagGenerator,
        extensions::idle::IdleDone,
        response::{Bye, Data, Response, Status, StatusBody, StatusKind, Tagged},
        secret::Secret,
        utils::escape_byte_string,
    },
};
use log::trace;
use thiserror::Error;

use crate::{coroutine::*, imap_try, send::*};

/// Refresh interval kept under the 29-minute RFC 2177 §3 cap.
#[cfg(feature = "client")]
const IDLE_DEFAULT_TIMEOUT: Duration = Duration::from_secs(29);

/// Failure causes during the IMAP IDLE flow.
#[derive(Clone, Debug, Error)]
pub enum ImapIdleError {
    #[error("IMAP IDLE failed: NO {0}")]
    No(String),
    #[error("IMAP IDLE failed: BAD {0}")]
    Bad(String),
    #[error("IMAP IDLE failed: BYE {0}")]
    Bye(String),

    #[error("IMAP IDLE failed: server returned a tagged response before the continuation request")]
    UnexpectedTagged,
    #[error("IMAP IDLE failed: server did not send the expected continuation request")]
    ExpectedContinuationRequest,
    #[error("IMAP IDLE failed: server did not return a tagged response to DONE")]
    MissingTagged,
    #[error("IMAP IDLE failed: reached unexpected EOF on stream")]
    Eof,
    #[error("IMAP IDLE failed: decode response error")]
    DecodingFailure(Secret<Box<[u8]>>),
    #[error("IMAP IDLE failed: parse response error: message is poisoned")]
    MessageIsPoisoned(Secret<Box<[u8]>>),
    #[error("IMAP IDLE failed: parse response error: message is too long")]
    MessageTooLong(Secret<Box<[u8]>>),

    #[error("IMAP IDLE failed: {0}")]
    Send(#[from] SendImapCommandError),
}

/// Batch of unilateral untagged responses received during an IDLE.
#[derive(Debug)]
pub struct ImapIdleEvent {
    pub untagged: Vec<StatusBody<'static>>,
    pub data: Vec<Data<'static>>,
}

/// Yield variants from the IDLE coroutine.
#[derive(Debug)]
pub enum ImapIdleYield {
    WantsRead,
    WantsWrite(Vec<u8>),
    Event(ImapIdleEvent),
}

impl From<ImapYield> for ImapIdleYield {
    fn from(y: ImapYield) -> Self {
        match y {
            ImapYield::WantsRead => ImapIdleYield::WantsRead,
            ImapYield::WantsWrite(bytes) => ImapIdleYield::WantsWrite(bytes),
        }
    }
}

/// Options for [`ImapIdle::new`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImapIdleOptions {
    /// Refresh interval; defaults to [`IDLE_DEFAULT_TIMEOUT`]. Unused
    /// without the `client` feature.
    pub timeout: Option<Duration>,
}

/// I/O-free IMAP IDLE coroutine yielding mailbox change events.
pub struct ImapIdle {
    tag: TagGenerator,
    state: State,
    wants_read: bool,
    codec: ResponseCodec,
    data: Vec<Data<'static>>,
    untagged: Vec<StatusBody<'static>>,
    bye: Option<Bye<'static>>,
    done: Arc<AtomicBool>,
    #[cfg_attr(not(feature = "client"), allow(dead_code))]
    opts: ImapIdleOptions,
    #[cfg(feature = "client")]
    timer: Option<Instant>,
}

impl ImapIdle {
    /// Flip `done` to `true` to wind down with a clean `DONE`.
    pub fn new(done: Arc<AtomicBool>, opts: ImapIdleOptions) -> Self {
        let mut tag = TagGenerator::new();

        let command = Command {
            tag: tag.generate(),
            body: CommandBody::Idle,
        };

        trace!("send IMAP command {command:?}");

        let state = State::Idle(SendImapCommand::new(CommandCodec::new(), command));

        Self {
            tag,
            state,
            wants_read: false,
            codec: ResponseCodec::new(),
            data: Vec::new(),
            untagged: Vec::new(),
            bye: None,
            done,
            opts,
            #[cfg(feature = "client")]
            timer: None,
        }
    }

    #[cfg(feature = "client")]
    fn timeout(&self) -> Duration {
        self.opts.timeout.unwrap_or(IDLE_DEFAULT_TIMEOUT)
    }

    #[cfg(feature = "client")]
    fn timed_out(&self) -> bool {
        self.timer
            .as_ref()
            .map(|t| t.elapsed() >= self.timeout())
            .unwrap_or(false)
    }
}

impl ImapCoroutine for ImapIdle {
    type Yield = ImapIdleYield;
    type Return = Result<(), ImapIdleError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        mut arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        #[cfg(feature = "client")]
        if self.timer.is_none() {
            self.timer = Some(Instant::now());
        }

        loop {
            trace!("idle: {}", self.state);

            if mem::take(&mut self.wants_read) {
                return ImapCoroutineState::Yielded(ImapIdleYield::WantsRead);
            }

            match &mut self.state {
                State::Idle(send) => {
                    // NOTE: servers may pack untagged responses into the same
                    // frame as `+ idling`; surface them immediately.
                    let out = imap_try!(send, fragmentizer, arg.take());

                    if let Some(bye) = out.bye {
                        let err = ImapIdleError::Bye(bye.text.to_string());
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    if let Some(Tagged { body, .. }) = out.tagged {
                        let err = match body.kind {
                            StatusKind::Ok => ImapIdleError::UnexpectedTagged,
                            StatusKind::No => ImapIdleError::No(body.text.to_string()),
                            StatusKind::Bad => ImapIdleError::Bad(body.text.to_string()),
                        };

                        return ImapCoroutineState::Complete(Err(err));
                    }

                    if out.continuation_request.is_none() {
                        let err = ImapIdleError::ExpectedContinuationRequest;
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    self.state = State::Read;

                    if !out.data.is_empty() || !out.untagged.is_empty() {
                        let event = ImapIdleEvent {
                            data: out.data,
                            untagged: out.untagged,
                        };

                        return ImapCoroutineState::Yielded(ImapIdleYield::Event(event));
                    }
                }
                State::Read => {
                    let done = self.done.load(Ordering::SeqCst);
                    #[cfg(feature = "client")]
                    let timed_out = self.timed_out();
                    #[cfg(not(feature = "client"))]
                    let timed_out = false;

                    if done || timed_out {
                        trace!("idle done: {done}");
                        trace!("idle timed out: {timed_out}");
                        let send = SendImapCommand::new(IdleDoneCodec::new(), IdleDone);
                        self.state = State::Done(send);
                        continue;
                    }

                    match arg.take() {
                        Some(&[]) => {
                            return ImapCoroutineState::Complete(Err(ImapIdleError::Eof));
                        }
                        Some(bytes) => {
                            trace!("read bytes: {}", escape_byte_string(bytes));
                            fragmentizer.enqueue_bytes(bytes);
                        }
                        None => {
                            self.wants_read = true;
                            continue;
                        }
                    }

                    loop {
                        match fragmentizer.progress() {
                            Some(info @ FragmentInfo::Line { .. }) => {
                                let bytes = fragmentizer.fragment_bytes(info);
                                trace!("read line fragment: {}", escape_byte_string(bytes));

                                if !fragmentizer.is_message_complete() {
                                    continue;
                                }

                                match fragmentizer.decode_message(&self.codec) {
                                    Ok(Response::Data(data)) => {
                                        self.data.push(data.into_static());
                                    }
                                    Ok(Response::Status(Status::Untagged(status))) => {
                                        self.untagged.push(status.into_static());
                                    }
                                    Ok(Response::Status(Status::Tagged(_))) => {}
                                    Ok(Response::Status(Status::Bye(bye))) => {
                                        self.bye.replace(bye.into_static());
                                    }
                                    Ok(Response::CommandContinuationRequest(_)) => {}
                                    Err(decode_err) => {
                                        let bytes = fragmentizer.message_bytes();
                                        let bytes = Secret::new(bytes.into());
                                        let err = match decode_err {
                                            DecodeMessageError::DecodingFailure(_)
                                            | DecodeMessageError::DecodingRemainder { .. } => {
                                                ImapIdleError::DecodingFailure(bytes)
                                            }
                                            DecodeMessageError::MessageTooLong { .. } => {
                                                ImapIdleError::MessageTooLong(bytes)
                                            }
                                            DecodeMessageError::MessagePoisoned { .. } => {
                                                ImapIdleError::MessageIsPoisoned(bytes)
                                            }
                                        };
                                        return ImapCoroutineState::Complete(Err(err));
                                    }
                                }
                            }
                            Some(info @ FragmentInfo::Literal { .. }) => {
                                let bytes = fragmentizer.fragment_bytes(info);
                                trace!("read literal fragment ({} bytes)", bytes.len());
                            }
                            None => {
                                let event = ImapIdleEvent {
                                    data: mem::take(&mut self.data),
                                    untagged: mem::take(&mut self.untagged),
                                };

                                return ImapCoroutineState::Yielded(ImapIdleYield::Event(event));
                            }
                        }
                    }
                }
                State::Done(send) => {
                    let out = imap_try!(send, fragmentizer, arg.take());

                    if let Some(bye) = out.bye {
                        let err = ImapIdleError::Bye(bye.text.to_string());
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    let Some(Tagged { body, .. }) = out.tagged else {
                        return ImapCoroutineState::Complete(Err(ImapIdleError::MissingTagged));
                    };

                    #[cfg(feature = "client")]
                    let timed_out = self
                        .timer
                        .take()
                        .map(|t| t.elapsed() >= self.timeout())
                        .unwrap_or(false);
                    #[cfg(not(feature = "client"))]
                    let timed_out = false;

                    return match body.kind {
                        StatusKind::Ok if timed_out => {
                            trace!("reached timeout, starting a new IDLE command");
                            let command = Command {
                                tag: self.tag.generate(),
                                body: CommandBody::Idle,
                            };
                            let send = SendImapCommand::new(CommandCodec::new(), command);
                            self.state = State::Idle(send);
                            continue;
                        }
                        StatusKind::Ok => ImapCoroutineState::Complete(Ok(())),
                        StatusKind::No => ImapCoroutineState::Complete(Err(ImapIdleError::No(
                            body.text.to_string(),
                        ))),
                        StatusKind::Bad => ImapCoroutineState::Complete(Err(ImapIdleError::Bad(
                            body.text.to_string(),
                        ))),
                    };
                }
            }
        }
    }
}

enum State {
    Idle(SendImapCommand<CommandCodec>),
    Read,
    Done(SendImapCommand<IdleDoneCodec>),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Idle(_) => f.write_str("send idle"),
            Self::Read => f.write_str("read events"),
            Self::Done(_) => f.write_str("send done"),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::str;

    use alloc::borrow::ToOwned;

    use super::*;

    #[test]
    fn shutdown_returns_ok() {
        let done = Arc::new(AtomicBool::new(false));
        let mut idle = ImapIdle::new(done.clone(), ImapIdleOptions::default());
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut idle, &mut frag, None);
        let line = str::from_utf8(&bytes).expect("utf8 command");
        let tag = first_word(line).to_owned();
        assert!(line.trim_end().ends_with("IDLE"));

        expect_wants_read(&mut idle, &mut frag);
        expect_wants_read_after(&mut idle, &mut frag, b"+ idling\r\n");

        done.store(true, Ordering::SeqCst);
        let bytes = expect_wants_write(&mut idle, &mut frag, None);
        assert_eq!(b"DONE\r\n", &*bytes);

        expect_wants_read(&mut idle, &mut frag);

        let reply = format!("{tag} OK IDLE terminated\r\n");
        expect_complete_ok(&mut idle, &mut frag, reply.as_bytes());
    }

    #[test]
    fn unsolicited_during_read_yields_event() {
        let done = Arc::new(AtomicBool::new(false));
        let mut idle = ImapIdle::new(done, ImapIdleOptions::default());
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let _ = expect_wants_write(&mut idle, &mut frag, None);
        expect_wants_read(&mut idle, &mut frag);
        expect_wants_read_after(&mut idle, &mut frag, b"+ idling\r\n");

        let event = expect_event(&mut idle, &mut frag, b"* 5 EXISTS\r\n");
        assert_eq!(1, event.data.len());
        assert!(event.untagged.is_empty());
    }

    #[test]
    fn unsolicited_piggyback_on_continuation_yields_event() {
        let done = Arc::new(AtomicBool::new(false));
        let mut idle = ImapIdle::new(done, ImapIdleOptions::default());
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let _ = expect_wants_write(&mut idle, &mut frag, None);
        expect_wants_read(&mut idle, &mut frag);

        let event = expect_event(&mut idle, &mut frag, b"+ idling\r\n* 10 EXISTS\r\n");
        assert_eq!(1, event.data.len());
    }

    #[test]
    fn idle_tagged_bad_returns_bad_error() {
        let done = Arc::new(AtomicBool::new(false));
        let mut idle = ImapIdle::new(done, ImapIdleOptions::default());
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut idle, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read(&mut idle, &mut frag);

        let reply = format!("{tag} BAD IDLE not supported\r\n");
        let err = expect_complete_err(&mut idle, &mut frag, reply.as_bytes());
        let ImapIdleError::Bad(text) = err else {
            panic!("expected ImapIdleError::Bad, got {err:?}");
        };
        assert_eq!(text, "IDLE not supported");
    }

    #[test]
    fn done_tagged_no_returns_no_error() {
        let done = Arc::new(AtomicBool::new(false));
        let mut idle = ImapIdle::new(done.clone(), ImapIdleOptions::default());
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        let bytes = expect_wants_write(&mut idle, &mut frag, None);
        let tag = first_word(str::from_utf8(&bytes).expect("utf8 command")).to_owned();

        expect_wants_read(&mut idle, &mut frag);
        expect_wants_read_after(&mut idle, &mut frag, b"+ idling\r\n");

        done.store(true, Ordering::SeqCst);
        let _ = expect_wants_write(&mut idle, &mut frag, None);
        expect_wants_read(&mut idle, &mut frag);

        let reply = format!("{tag} NO IDLE aborted\r\n");
        let err = expect_complete_err(&mut idle, &mut frag, reply.as_bytes());
        let ImapIdleError::No(text) = err else {
            panic!("expected ImapIdleError::No, got {err:?}");
        };
        assert_eq!(text, "IDLE aborted");
    }

    // --- utils

    fn expect_wants_write(
        cor: &mut ImapIdle,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> Vec<u8> {
        match cor.resume(frag, arg) {
            ImapCoroutineState::Yielded(ImapIdleYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut ImapIdle, frag: &mut Fragmentizer) {
        match cor.resume(frag, None) {
            ImapCoroutineState::Yielded(ImapIdleYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_wants_read_after(cor: &mut ImapIdle, frag: &mut Fragmentizer, arg: &[u8]) {
        match cor.resume(frag, Some(arg)) {
            ImapCoroutineState::Yielded(ImapIdleYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_event(cor: &mut ImapIdle, frag: &mut Fragmentizer, arg: &[u8]) -> ImapIdleEvent {
        match cor.resume(frag, Some(arg)) {
            ImapCoroutineState::Yielded(ImapIdleYield::Event(event)) => event,
            state => panic!("expected Event, got {state:?}"),
        }
    }

    fn expect_complete_ok(cor: &mut ImapIdle, frag: &mut Fragmentizer, reply: &[u8]) {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Complete(Ok(())) => {}
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut ImapIdle,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> ImapIdleError {
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
