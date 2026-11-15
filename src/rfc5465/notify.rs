//! IMAP NOTIFY coroutine registering the events the server reports.
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
//!     codec::{fragmentizer::Fragmentizer, imap_types::core::TagGenerator},
//!     coroutine::{ImapCoroutine, ImapCoroutineState, ImapYield},
//!     rfc5465::notify::ImapNotifySet,
//!     types::extensions::notify::Notify,
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negotiated, IMAP-authenticated)
//! let mut stream = TcpStream::connect("localhost:143").unwrap();
//!
//! let mut fragmentizer = Fragmentizer::new(50 * 1024 * 1024);
//! let mut buf = [0u8; 4096];
//!
//! // See rfc5465::watch for a NOTIFY SET.
//! let mut coroutine = ImapNotifySet::new(Notify::None);
//! let mut tags = TagGenerator::new();
//! let mut tag;
//! let mut arg = None;
//!
//! let data = loop {
//!     match coroutine.resume(&mut fragmentizer, arg.take()) {
//!         ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         ImapCoroutineState::Yielded(ImapYield::WantsTag) => {
//!             tag = tags.generate();
//!             arg = Some(tag.as_ref().as_bytes());
//!         }
//!         ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         ImapCoroutineState::Complete(Ok(out)) => break out.data,
//!         ImapCoroutineState::Complete(Err(err)) => panic!("{err}"),
//!     }
//! };
//!
//! println!("{data:?}");
//! ```

use core::fmt;

use alloc::{string::String, string::ToString, vec::Vec};

use imap_codec::{
    CommandCodec,
    fragmentizer::Fragmentizer,
    imap_types::{
        command::CommandBody,
        extensions::notify::{Notify, SupportedEvent},
        response::{Code, Data, StatusKind, Tagged},
    },
};
use log::trace;
use thiserror::Error;

use crate::{coroutine::*, imap_try, send::*};

/// Failure causes during the IMAP NOTIFY flow.
#[derive(Clone, Debug, Error)]
pub enum ImapNotifySetError {
    /// The server refused an event it does not support, with a
    /// `BADEVENT` response code.
    ///
    /// `events` are the names the code lists. RFC 5465 has the server
    /// list the events it supports; Dovecot (2.4) lists the refused
    /// ones instead, without the parentheses, which is read here too.
    #[error("IMAP NOTIFY failed: unsupported event: {status}")]
    BadEvent {
        /// The event names the `BADEVENT` code lists.
        events: Vec<String>,
        /// The refusal.
        status: ImapStatusError,
    },
    /// The server rejected the NOTIFY command with a NO response.
    #[error("IMAP NOTIFY failed: NO {0}")]
    No(ImapStatusError),
    /// The server rejected the NOTIFY command with a BAD response.
    #[error("IMAP NOTIFY failed: BAD {0}")]
    Bad(ImapStatusError),
    /// The server closed the connection with a BYE response.
    #[error("IMAP NOTIFY failed: BYE {0}")]
    Bye(String),
    /// The server never answered with a tagged response.
    #[error("IMAP NOTIFY failed: server did not return a tagged response")]
    MissingTagged,
    /// The underlying send sub-coroutine failed.
    #[error("IMAP NOTIFY failed: {0}")]
    Send(#[from] ImapSendError),
}

/// I/O-free IMAP NOTIFY coroutine.
pub struct ImapNotifySet {
    state: State,
}

impl ImapNotifySet {
    /// Creates a coroutine that sends `NOTIFY SET` or `NOTIFY NONE`.
    ///
    /// It returns the data read with the completion: with
    /// `Notify::Set { status: true, .. }`, a STATUS response for every
    /// mailbox the groups name.
    pub fn new(notify: Notify<'static>) -> Self {
        let body = CommandBody::Notify(notify);

        trace!("send IMAP command {body:?}");

        let state = State::Send(ImapSend::command(body));

        Self { state }
    }
}

impl ImapCoroutine for ImapNotifySet {
    type Yield = ImapYield;
    type Return = Result<ImapOutput<Vec<Data<'static>>>, ImapNotifySetError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        match &mut self.state {
            State::Send(send) => {
                let out = imap_try!(send, fragmentizer, arg);
                let alerts = out.alerts();

                if let Some(bye) = out.bye {
                    let err = ImapNotifySetError::Bye(bye.text.to_string());
                    return ImapCoroutineState::Complete(Err(err));
                }

                let Some(Tagged { body, .. }) = out.tagged else {
                    let err = ImapNotifySetError::MissingTagged;
                    return ImapCoroutineState::Complete(Err(err));
                };

                match body.kind {
                    StatusKind::Ok => ImapCoroutineState::Complete(Ok(ImapOutput {
                        data: out.data,
                        alerts,
                        skipped: out.skipped,
                        partial: out.partial,
                    })),
                    StatusKind::No => {
                        let status = ImapStatusError::from(body);
                        let err = match bad_events(status.code.as_ref()) {
                            Some(events) => ImapNotifySetError::BadEvent { events, status },
                            None => ImapNotifySetError::No(status),
                        };
                        ImapCoroutineState::Complete(Err(err))
                    }
                    StatusKind::Bad => {
                        let err = ImapNotifySetError::Bad(body.into());
                        ImapCoroutineState::Complete(Err(err))
                    }
                }
            }
        }
    }
}

/// The event names of a `BADEVENT` code, in the RFC's form or Dovecot's.
fn bad_events(code: Option<&Code<'_>>) -> Option<Vec<String>> {
    match code? {
        Code::BadEvent(events) => Some(
            events
                .as_ref()
                .iter()
                .map(|event| match event {
                    SupportedEvent::Known(name) => name.as_str().to_string(),
                    SupportedEvent::Other(other) => other.inner().as_ref().to_string(),
                })
                .collect(),
        ),
        Code::Other(other) => {
            let text = core::str::from_utf8(other.inner()).ok()?;
            let (name, rest) = text.split_once(' ').unwrap_or((text, ""));
            name.eq_ignore_ascii_case("BADEVENT")
                .then(|| rest.split_whitespace().map(ToString::to_string).collect())
        }
        _ => None,
    }
}

enum State {
    Send(ImapSend<CommandCodec>),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(_) => f.write_str("send notify"),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::str;

    use alloc::{borrow::ToOwned, vec, vec::Vec};

    use imap_codec::imap_types::{
        core::Vec1,
        extensions::notify::{
            EventGroups, FilterMailboxes, MailboxEvents, MailboxGroup, MessageEvents,
        },
    };

    use crate::rfc5465::notify::*;

    fn personal() -> Notify<'static> {
        let group = MailboxGroup {
            filter: FilterMailboxes::Personal,
            events: Some(MailboxEvents::WithMessage {
                message: MessageEvents {
                    flag_change: true,
                    annotation_change: false,
                },
                others: vec![],
            }),
        };

        Notify::Set {
            status: true,
            groups: EventGroups::Others(Vec1::from(group)),
        }
    }

    fn sent(notify: Notify<'static>) -> (ImapNotifySet, Fragmentizer, String) {
        let mut cor = ImapNotifySet::new(notify);
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        match cor.resume(&mut frag, None) {
            ImapCoroutineState::Yielded(ImapYield::WantsTag) => {}
            state => panic!("expected WantsTag, got {state:?}"),
        }
        let line = match cor.resume(&mut frag, Some(b"A1")) {
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
                str::from_utf8(&bytes).expect("utf8 command").to_owned()
            }
            state => panic!("expected WantsWrite, got {state:?}"),
        };
        match cor.resume(&mut frag, None) {
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }

        (cor, frag, line)
    }

    fn complete(
        cor: &mut ImapNotifySet,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> Result<ImapOutput<Vec<Data<'static>>>, ImapNotifySetError> {
        match cor.resume(frag, Some(reply)) {
            ImapCoroutineState::Complete(result) => result,
            state => panic!("expected Complete, got {state:?}"),
        }
    }

    #[test]
    fn set_status_returns_the_status_of_every_mailbox() {
        let (mut cor, mut frag, line) = sent(personal());
        assert_eq!(
            "A1 NOTIFY SET STATUS (PERSONAL (MessageNew MessageExpunge FlagChange))\r\n",
            line
        );

        let reply = b"* STATUS INBOX (MESSAGES 2 UIDNEXT 3 UIDVALIDITY 1)\r\n\
                      * STATUS Sent (MESSAGES 0 UIDNEXT 1 UIDVALIDITY 2)\r\n\
                      A1 OK NOTIFY completed\r\n";
        let out = complete(&mut cor, &mut frag, reply).expect("NOTIFY succeeds");
        assert_eq!(2, out.data.len());
        assert!(matches!(out.data[0], Data::Status { .. }));
    }

    #[test]
    fn none_cancels_the_notifications() {
        let (mut cor, mut frag, line) = sent(Notify::None);
        assert_eq!("A1 NOTIFY NONE\r\n", line);

        let out = complete(&mut cor, &mut frag, b"A1 OK done\r\n").expect("NOTIFY succeeds");
        assert!(out.data.is_empty());
    }

    #[test]
    fn badevent_names_the_events_it_lists() {
        let (mut cor, mut frag, _) = sent(personal());

        let reply = b"A1 NO [BADEVENT (MessageNew MessageExpunge XFoo)] Unsupported\r\n";
        let err = complete(&mut cor, &mut frag, reply).expect_err("NOTIFY refused");
        let ImapNotifySetError::BadEvent { events, status } = err else {
            panic!("expected BadEvent, got {err:?}");
        };
        assert_eq!(vec!["MessageNew", "MessageExpunge", "XFoo"], events);
        assert_eq!("Unsupported", status.text);
    }

    #[test]
    fn dovecots_badevent_names_the_events_it_lists() {
        let (mut cor, mut frag, _) = sent(personal());

        let reply = b"A1 NO [BADEVENT AnnotationChange ServerMetadataChange] Unsupported NOTIFY events.\r\n";
        let err = complete(&mut cor, &mut frag, reply).expect_err("NOTIFY refused");
        let ImapNotifySetError::BadEvent { events, .. } = err else {
            panic!("expected BadEvent, got {err:?}");
        };
        assert_eq!(vec!["AnnotationChange", "ServerMetadataChange"], events);
    }

    #[test]
    fn other_refusals_stay_no_and_bad() {
        let (mut cor, mut frag, _) = sent(personal());
        let err = complete(&mut cor, &mut frag, b"A1 NO [TRYCREATE] nope\r\n").expect_err("NO");
        assert!(matches!(err, ImapNotifySetError::No(_)), "{err:?}");

        let (mut cor, mut frag, _) = sent(personal());
        let err = complete(&mut cor, &mut frag, b"A1 BAD Invalid arguments\r\n").expect_err("BAD");
        assert!(matches!(err, ImapNotifySetError::Bad(_)), "{err:?}");
    }
}
