//! I/O-free coroutine to watch IMAP mailbox changes using the IDLE extension
//! (RFC 2177).
//!
//! Shutdown is cooperative: the caller flips the [`AtomicBool`] handed to
//! [`ImapIdle::new`], the coroutine reads it on its next loop iteration and
//! transitions from [`State::Read`] to [`State::Done`], sending `DONE` cleanly
//! before completing with `Ok(())`. When the `client` feature is enabled, the
//! coroutine also refreshes the IDLE every [`ImapIdleOptions::timeout`]
//! (default 29s) to keep the connection alive against servers that drop long
//! idle sockets.

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

/// Default IDLE refresh window when no [`ImapIdleOptions::timeout`]
/// override is supplied. Set conservatively below the 29-minute upper
/// bound recommended by RFC 2177 §3 to survive aggressive middleboxes.
#[cfg(feature = "client")]
const IDLE_DEFAULT_TIMEOUT: Duration = Duration::from_secs(29);

/// Errors that can occur during IDLE progression.
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

/// One batch of unilateral untagged responses delivered during an
/// IDLE.
#[derive(Debug)]
pub struct ImapIdleEvent {
    pub untagged: Vec<StatusBody<'static>>,
    pub data: Vec<Data<'static>>,
}

/// Per-coroutine Yield: socket I/O step requests on one axis, untagged-response
/// batches on the other. The driver dispatches on the variant: I/O variants
/// pump the IMAP socket; [`Self::Event`] is delivered to the caller (callback /
/// channel / async stream).
#[derive(Debug)]
pub enum ImapIdleYield {
    /// Socket: read more bytes and feed them back on the next resume.
    WantsRead,
    /// Socket: write these bytes; the next resume typically takes `None`.
    WantsWrite(Vec<u8>),
    /// Domain: one batch of unilateral untagged responses received during the
    /// IDLE.
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

/// Optional knobs for [`ImapIdle::new`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImapIdleOptions {
    /// Server-side refresh interval. When the `client` feature is on and the
    /// timer elapses, the coroutine sends `DONE` and re-issues `IDLE` to keep
    /// the connection from being dropped by aggressive middleboxes. When
    /// `None`, falls back to [`IDLE_DEFAULT_TIMEOUT`]. Without the `client`
    /// feature this field is unused since [`Instant`] is unavailable in
    /// `no_std`.
    pub timeout: Option<Duration>,
}

/// I/O-free coroutine watching IMAP mailbox changes via IDLE.
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
    /// Creates a new coroutine.
    ///
    /// `done` is the shared shutdown flag: flip it to `true` to ask the
    /// coroutine to wind down at its next chance (sends `DONE` and completes
    /// with `Ok(())`). Pass `Arc::new(AtomicBool::new(false))` when no external
    /// shutdown is needed.
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
                    // NOTE: an IMAP server can legally pack the
                    // continuation-request line and one or more unsolicited
                    // untagged responses into the same physical send, e.g. `+
                    // idling\r\n* 10 FETCH …` when a flag change happens just
                    // before the server processes our `IDLE`. SendImapCommand
                    // parses them all in one resume and returns them via `data`
                    // / `untagged`; surface them here so the caller sees the
                    // changes immediately instead of waiting for the next
                    // socket read.
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
                                    Ok(Response::Status(Status::Tagged(_))) => {
                                        // ignore tagged during IDLE.
                                    }
                                    Ok(Response::Status(Status::Bye(bye))) => {
                                        self.bye.replace(bye.into_static());
                                    }
                                    Ok(Response::CommandContinuationRequest(_)) => {
                                        // ignore continuation request during IDLE.
                                    }
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
    /// Send the IDLE command and await the continuation request.
    Idle(SendImapCommand<CommandCodec>),
    /// Read unilateral responses until the shutdown flag is set or the refresh
    /// timeout elapses.
    Read,
    /// Send the DONE command and await the tagged response.
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

    /// Happy path: client sends `IDLE`, server replies with the
    /// continuation request, caller flips the shutdown flag, client
    /// sends `DONE`, server returns tagged OK.
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

    /// Unilateral responses arriving during the read phase are
    /// emitted as a single `Event`.
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

    /// Server piggy-backs unsolicited responses on the continuation
    /// request frame: the coroutine emits them immediately, then
    /// transitions to the read phase.
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

    /// Tagged BAD before the continuation request: surface text
    /// verbatim.
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

    /// Tagged NO returned after DONE: surface text verbatim.
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
