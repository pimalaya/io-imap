//! IMAP NOTIFY watch: one NOTIFY, then IDLE, yielding the
//! notifications of every mailbox the NOTIFY names.
//!
//! The notifications are the responses the server already sends for
//! a change (STATUS for a mailbox other than the selected one, EXISTS,
//! EXPUNGE and FETCH for the selected one, LIST for a mailbox created,
//! deleted or renamed), yielded as they arrive. IDLE is held only so
//! the connection is read and kept alive; it adds nothing to what the
//! server reports (RFC 5465 section 5).
//!
//! Without CONDSTORE a mailbox's STATUS carries no HIGHESTMODSEQ, so
//! a flag change other than `\Seen` in a mailbox that isn't selected
//! goes unreported (RFC 5465 section 5.1). The watch therefore ENABLEs
//! CONDSTORE first, as [`ImapNotifyCondstore`] chooses: by default
//! when the server advertises ENABLE and CONDSTORE.
//!
//! A server that can no longer tell every change sends
//! `NOTIFICATIONOVERFLOW` and stops notifying: the watch yields that
//! event, then ends with [`ImapNotifyWatchError::Overflow`], and the
//! caller resyncs before it watches again.
//!
//! What the caller already knows must be read after the NOTIFY, not
//! before, or a change in between is never notified (RFC 5465 erratum
//! 2318): `NOTIFY SET STATUS` does both at once, and without STATUS
//! the caller reads only once [`ImapNotifyWatch::opened`] is true.
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
//!     codec::{
//!         fragmentizer::Fragmentizer,
//!         imap_types::core::{TagGenerator, Vec1},
//!     },
//!     coroutine::{ImapCoroutine, ImapCoroutineState},
//!     rfc5465::watch::{ImapNotifyWatch, ImapNotifyWatchYield},
//!     types::extensions::notify::{
//!         EventGroups, FilterMailboxes, MailboxEvents, MailboxGroup, Notify,
//!     },
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negotiated, IMAP-authenticated)
//! let mut stream = TcpStream::connect("localhost:143").unwrap();
//!
//! let mut fragmentizer = Fragmentizer::new(50 * 1024 * 1024);
//! let mut buf = [0u8; 4096];
//!
//! // New mail and expunges in every personal mailbox.
//! let events = MailboxEvents::WithMessage { message: Default::default(), others: vec![] };
//! let group = MailboxGroup { filter: FilterMailboxes::Personal, events: Some(events) };
//! let notify = Notify::Set { status: false, groups: EventGroups::Others(Vec1::from(group)) };
//! // The server's advertised capabilities decide the ENABLE CONDSTORE.
//! let capability = [];
//! let shutdown = Arc::new(AtomicBool::new(false));
//! let opts = Default::default();
//! let mut coroutine = ImapNotifyWatch::new(&capability, notify, shutdown.clone(), opts);
//! let mut tags = TagGenerator::new();
//! let mut tag;
//! let mut arg = None;
//!
//! loop {
//!     match coroutine.resume(&mut fragmentizer, arg.take()) {
//!         ImapCoroutineState::Yielded(ImapNotifyWatchYield::WantsTag) => {
//!             tag = tags.generate();
//!             arg = Some(tag.as_ref().as_bytes());
//!         }
//!         ImapCoroutineState::Yielded(ImapNotifyWatchYield::WantsWrite(bytes)) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         ImapCoroutineState::Yielded(ImapNotifyWatchYield::WantsRead) => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         ImapCoroutineState::Yielded(ImapNotifyWatchYield::Event(event)) => {
//!             println!("{event:?}");
//!         }
//!         ImapCoroutineState::Complete(Ok(())) => break,
//!         ImapCoroutineState::Complete(Err(err)) => panic!("{err}"),
//!     }
//! }
//! ```

use core::{fmt, mem, sync::atomic::AtomicBool, time::Duration};

use alloc::{sync::Arc, vec::Vec};

use imap_codec::{
    fragmentizer::Fragmentizer,
    imap_types::{
        core::Vec1,
        extensions::{enable::CapabilityEnable, notify::Notify},
        response::{Capability, Code},
    },
};
use log::debug;
use thiserror::Error;

use crate::{
    coroutine::*,
    rfc2177::idle::{ImapIdle, ImapIdleError, ImapIdleEvent, ImapIdleOptions, ImapIdleYield},
    rfc5161::enable::{ImapExtensionEnable, ImapExtensionEnableError},
    rfc5465::notify::{ImapNotifySet, ImapNotifySetError},
};

/// Failure causes of a NOTIFY watch.
#[derive(Clone, Debug, Error)]
pub enum ImapNotifyWatchError {
    /// CONDSTORE was required but the server doesn't advertise both
    /// ENABLE and CONDSTORE, or its ENABLED doesn't list CONDSTORE.
    #[error("IMAP server does not support or enable CONDSTORE")]
    CondstoreNotSupported,
    /// The ENABLE CONDSTORE round failed.
    #[error(transparent)]
    Enable(#[from] ImapExtensionEnableError),
    /// The NOTIFY command failed.
    #[error(transparent)]
    Notify(#[from] ImapNotifySetError),
    /// The IDLE holding the connection failed.
    #[error(transparent)]
    Idle(#[from] ImapIdleError),
    /// The server sent `NOTIFICATIONOVERFLOW`: it stopped notifying,
    /// and changes may have gone unreported.
    #[error("IMAP NOTIFY watch failed: the server's notifications overflowed")]
    Overflow,
}

/// Yield variants of [`ImapNotifyWatch`].
#[derive(Debug)]
pub enum ImapNotifyWatchYield {
    /// The caller resumes with the tag of the next command.
    WantsTag,
    /// The caller reads bytes from the stream and resumes with them.
    WantsRead,
    /// The caller writes the given bytes to the stream and resumes.
    WantsWrite(Vec<u8>),
    /// Notifications to consume; the coroutine keeps running.
    ///
    /// The first event of a `NOTIFY SET STATUS` holds the STATUS of
    /// every mailbox the NOTIFY names.
    Event(ImapIdleEvent),
}

impl From<ImapYield> for ImapNotifyWatchYield {
    fn from(y: ImapYield) -> Self {
        match y {
            ImapYield::WantsTag => Self::WantsTag,
            ImapYield::WantsRead => Self::WantsRead,
            ImapYield::WantsWrite(bytes) => Self::WantsWrite(bytes),
        }
    }
}

/// Whether a NOTIFY watch ENABLEs CONDSTORE before its NOTIFY.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ImapNotifyCondstore {
    /// Never send ENABLE.
    Disable,
    /// ENABLE CONDSTORE when the server advertises ENABLE and
    /// CONDSTORE, and watch without it otherwise or when its ENABLED
    /// doesn't list CONDSTORE.
    #[default]
    Prefer,
    /// ENABLE CONDSTORE, failing with
    /// [`ImapNotifyWatchError::CondstoreNotSupported`] before sending
    /// anything when the server doesn't advertise it, or after the
    /// ENABLE when its ENABLED doesn't list CONDSTORE.
    Require,
}

/// Options for [`ImapNotifyWatch::new`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImapNotifyWatchOptions {
    /// How long an IDLE is held before it is re-issued, `None` taking
    /// io-imap's own default.
    pub idle_timeout: Option<Duration>,
    /// Whether to ENABLE CONDSTORE before the NOTIFY.
    pub condstore: ImapNotifyCondstore,
}

/// I/O-free NOTIFY watch coroutine.
pub struct ImapNotifyWatch {
    state: State,
    opened: bool,
    condstore: bool,
    require: bool,
    done: Arc<AtomicBool>,
    idle_timeout: Option<Duration>,
}

impl ImapNotifyWatch {
    /// Creates a watch that sends `notify`, then holds IDLE until
    /// `done` is set, yielding what the server reports; `capability`
    /// decides whether CONDSTORE can be enabled first.
    pub fn new(
        capability: &[Capability<'static>],
        notify: Notify<'static>,
        done: Arc<AtomicBool>,
        opts: ImapNotifyWatchOptions,
    ) -> Self {
        let advertised =
            capability.contains(&Capability::Enable) && capability.contains(&Capability::CondStore);
        let state = match (opts.condstore, advertised) {
            (ImapNotifyCondstore::Prefer | ImapNotifyCondstore::Require, true) => {
                let capabilities = Vec1::from(CapabilityEnable::CondStore);
                State::Enable(ImapExtensionEnable::new(capabilities), notify)
            }
            (ImapNotifyCondstore::Require, false) => State::NotSupported,
            _ => State::Notify(ImapNotifySet::new(notify)),
        };

        Self {
            state,
            opened: false,
            condstore: false,
            require: opts.condstore == ImapNotifyCondstore::Require,
            done,
            idle_timeout: opts.idle_timeout,
        }
    }

    /// Whether the server accepted the NOTIFY.
    pub fn opened(&self) -> bool {
        self.opened
    }

    /// Whether the server's ENABLED listed CONDSTORE.
    pub fn condstore(&self) -> bool {
        self.condstore
    }
}

impl ImapCoroutine for ImapNotifyWatch {
    type Yield = ImapNotifyWatchYield;
    type Return = Result<(), ImapNotifyWatchError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        mut arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        loop {
            match mem::replace(&mut self.state, State::Overflowed) {
                State::Enable(mut enable, notify) => {
                    match enable.resume(fragmentizer, arg.take()) {
                        ImapCoroutineState::Yielded(y) => {
                            self.state = State::Enable(enable, notify);
                            return ImapCoroutineState::Yielded(y.into());
                        }
                        ImapCoroutineState::Complete(Err(err)) => {
                            return ImapCoroutineState::Complete(Err(err.into()));
                        }
                        ImapCoroutineState::Complete(Ok(enabled)) => {
                            // NOTE: RFC 5161 §3.2: what ENABLED does not list,
                            // a bare OK included, is not enabled.
                            self.condstore = enabled
                                .iter()
                                .flatten()
                                .any(|capability| *capability == CapabilityEnable::CondStore);

                            if !self.condstore {
                                if self.require {
                                    let err = ImapNotifyWatchError::CondstoreNotSupported;
                                    return ImapCoroutineState::Complete(Err(err));
                                }
                                debug!("condstore not enabled, watching without it");
                            }

                            self.state = State::Notify(ImapNotifySet::new(notify));
                            debug!("{}", self.state);
                        }
                    }
                }
                State::Notify(mut notify) => match notify.resume(fragmentizer, arg.take()) {
                    ImapCoroutineState::Yielded(y) => {
                        self.state = State::Notify(notify);
                        return ImapCoroutineState::Yielded(y.into());
                    }
                    ImapCoroutineState::Complete(Err(err)) => {
                        return ImapCoroutineState::Complete(Err(err.into()));
                    }
                    ImapCoroutineState::Complete(Ok(out)) => {
                        self.opened = true;
                        let opts = ImapIdleOptions {
                            timeout: self.idle_timeout,
                        };
                        self.state = State::Idle(ImapIdle::new(self.done.clone(), opts));
                        debug!("{}", self.state);

                        if !out.data.is_empty() {
                            let event = ImapIdleEvent {
                                untagged: Vec::new(),
                                data: out.data,
                            };
                            return ImapCoroutineState::Yielded(ImapNotifyWatchYield::Event(event));
                        }
                    }
                },
                State::Idle(mut idle) => match idle.resume(fragmentizer, arg.take()) {
                    ImapCoroutineState::Yielded(ImapIdleYield::Event(event)) => {
                        self.state = if overflowed(&event) {
                            State::Overflowed
                        } else {
                            State::Idle(idle)
                        };
                        return ImapCoroutineState::Yielded(ImapNotifyWatchYield::Event(event));
                    }
                    ImapCoroutineState::Yielded(ImapIdleYield::WantsTag) => {
                        self.state = State::Idle(idle);
                        return ImapCoroutineState::Yielded(ImapNotifyWatchYield::WantsTag);
                    }
                    ImapCoroutineState::Yielded(ImapIdleYield::WantsRead) => {
                        self.state = State::Idle(idle);
                        return ImapCoroutineState::Yielded(ImapNotifyWatchYield::WantsRead);
                    }
                    ImapCoroutineState::Yielded(ImapIdleYield::WantsWrite(bytes)) => {
                        self.state = State::Idle(idle);
                        return ImapCoroutineState::Yielded(ImapNotifyWatchYield::WantsWrite(
                            bytes,
                        ));
                    }
                    ImapCoroutineState::Complete(result) => {
                        return ImapCoroutineState::Complete(result.map_err(Into::into));
                    }
                },
                State::Overflowed => {
                    return ImapCoroutineState::Complete(Err(ImapNotifyWatchError::Overflow));
                }
                State::NotSupported => {
                    let err = ImapNotifyWatchError::CondstoreNotSupported;
                    return ImapCoroutineState::Complete(Err(err));
                }
            }
        }
    }
}

fn overflowed(event: &ImapIdleEvent) -> bool {
    event
        .untagged
        .iter()
        .any(|status| matches!(status.code, Some(Code::NotificationOverflow)))
}

enum State {
    Enable(ImapExtensionEnable, Notify<'static>),
    Notify(ImapNotifySet),
    Idle(ImapIdle),
    Overflowed,
    NotSupported,
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Enable(..) => f.write_str("enable condstore"),
            Self::Notify(_) => f.write_str("send notify"),
            Self::Idle(_) => f.write_str("idle for notifications"),
            Self::Overflowed => f.write_str("notifications overflowed"),
            Self::NotSupported => f.write_str("condstore not supported"),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::{str, sync::atomic::Ordering};

    use alloc::{borrow::ToOwned, string::String, vec};

    use imap_codec::imap_types::{
        core::Vec1,
        extensions::notify::{
            EventGroups, FilterMailboxes, MailboxEvents, MailboxGroup, MessageEvents,
        },
        response::Data,
    };

    use crate::rfc5465::watch::*;

    const CONDSTORE: &[Capability<'static>] = &[Capability::Enable, Capability::CondStore];

    fn watch(
        status: bool,
        capability: &[Capability<'static>],
    ) -> (ImapNotifyWatch, Arc<AtomicBool>) {
        watch_with(status, capability, ImapNotifyCondstore::Prefer)
    }

    fn watch_with(
        status: bool,
        capability: &[Capability<'static>],
        condstore: ImapNotifyCondstore,
    ) -> (ImapNotifyWatch, Arc<AtomicBool>) {
        let group = MailboxGroup {
            filter: FilterMailboxes::Personal,
            events: Some(MailboxEvents::WithMessage {
                message: MessageEvents::default(),
                others: vec![],
            }),
        };
        let notify = Notify::Set {
            status,
            groups: EventGroups::Others(Vec1::from(group)),
        };
        let done = Arc::new(AtomicBool::new(false));
        let opts = ImapNotifyWatchOptions {
            condstore,
            ..Default::default()
        };
        let watch = ImapNotifyWatch::new(capability, notify, done.clone(), opts);
        (watch, done)
    }

    fn step(
        cor: &mut ImapNotifyWatch,
        frag: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<ImapNotifyWatchYield, Result<(), ImapNotifyWatchError>> {
        cor.resume(frag, arg)
    }

    fn written(
        state: ImapCoroutineState<ImapNotifyWatchYield, Result<(), ImapNotifyWatchError>>,
    ) -> String {
        match state {
            ImapCoroutineState::Yielded(ImapNotifyWatchYield::WantsWrite(bytes)) => {
                str::from_utf8(&bytes).expect("utf8").to_owned()
            }
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn event(
        state: ImapCoroutineState<ImapNotifyWatchYield, Result<(), ImapNotifyWatchError>>,
    ) -> ImapIdleEvent {
        match state {
            ImapCoroutineState::Yielded(ImapNotifyWatchYield::Event(event)) => event,
            state => panic!("expected Event, got {state:?}"),
        }
    }

    fn wants(
        state: ImapCoroutineState<ImapNotifyWatchYield, Result<(), ImapNotifyWatchError>>,
        what: &str,
    ) {
        match (what, state) {
            ("tag", ImapCoroutineState::Yielded(ImapNotifyWatchYield::WantsTag))
            | ("read", ImapCoroutineState::Yielded(ImapNotifyWatchYield::WantsRead)) => {}
            (_, state) => panic!("expected {what}, got {state:?}"),
        }
    }

    /// Answers the watch's ENABLE CONDSTORE with `reply`.
    fn enabled(cor: &mut ImapNotifyWatch, frag: &mut Fragmentizer, reply: &[u8]) {
        wants(step(cor, frag, None), "tag");
        assert_eq!(
            "A0 ENABLE CONDSTORE\r\n",
            written(step(cor, frag, Some(b"A0")))
        );
        wants(step(cor, frag, None), "read");
        wants(step(cor, frag, Some(reply)), "tag");
    }

    /// Runs the watch from its NOTIFY up to its IDLE continuation.
    fn idling(
        cor: &mut ImapNotifyWatch,
        frag: &mut Fragmentizer,
        reply: &[u8],
    ) -> Option<ImapIdleEvent> {
        notifying(cor, frag, None, reply)
    }

    /// `idling`, after `ENABLE CONDSTORE` was answered with `enable`.
    fn notifying(
        cor: &mut ImapNotifyWatch,
        frag: &mut Fragmentizer,
        enable: Option<&[u8]>,
        reply: &[u8],
    ) -> Option<ImapIdleEvent> {
        match enable {
            Some(enable) => enabled(cor, frag, enable),
            None => wants(step(cor, frag, None), "tag"),
        }
        let line = written(step(cor, frag, Some(b"A1")));
        assert!(line.starts_with("A1 NOTIFY SET "), "{line}");
        wants(step(cor, frag, None), "read");
        assert!(!cor.opened());

        let mut first = None;
        match step(cor, frag, Some(reply)) {
            ImapCoroutineState::Yielded(ImapNotifyWatchYield::Event(event)) => {
                first = Some(event);
                wants(step(cor, frag, None), "tag");
            }
            state => wants(state, "tag"),
        }
        assert!(cor.opened());

        assert_eq!("A2 IDLE\r\n", written(step(cor, frag, Some(b"A2"))));
        wants(step(cor, frag, None), "read");
        let none = step(cor, frag, Some(b"+ idling\r\n"));
        wants(none, "read");
        first
    }

    #[test]
    fn notifications_arrive_while_idling() {
        let (mut cor, done) = watch(false, &[]);
        let mut frag = Fragmentizer::new(1 << 20);

        assert!(idling(&mut cor, &mut frag, b"A1 OK NOTIFY done\r\n").is_none());

        let reply = b"* STATUS Lists (MESSAGES 3 UIDNEXT 9)\r\n";
        let notified = event(step(&mut cor, &mut frag, Some(reply)));
        assert!(matches!(notified.data[..], [Data::Status { .. }]));

        done.store(true, Ordering::SeqCst);
        assert_eq!("DONE\r\n", written(step(&mut cor, &mut frag, None)));
        wants(step(&mut cor, &mut frag, None), "read");
        match step(&mut cor, &mut frag, Some(b"A2 OK IDLE done\r\n")) {
            ImapCoroutineState::Complete(Ok(())) => {}
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    #[test]
    fn set_status_yields_the_status_of_every_mailbox_first() {
        let (mut cor, _) = watch(true, &[]);
        let mut frag = Fragmentizer::new(1 << 20);

        let reply = b"* STATUS INBOX (MESSAGES 2 UIDNEXT 3)\r\nA1 OK NOTIFY done\r\n";
        let first = idling(&mut cor, &mut frag, reply).expect("STATUS event");
        assert!(matches!(first.data[..], [Data::Status { .. }]));
    }

    #[test]
    fn an_overflow_ends_the_watch_after_its_event() {
        let (mut cor, _) = watch(false, &[]);
        let mut frag = Fragmentizer::new(1 << 20);
        idling(&mut cor, &mut frag, b"A1 OK NOTIFY done\r\n");

        let reply = b"* OK [NOTIFICATIONOVERFLOW] too many\r\n";
        let notified = event(step(&mut cor, &mut frag, Some(reply)));
        assert_eq!(1, notified.untagged.len());
        match step(&mut cor, &mut frag, None) {
            ImapCoroutineState::Complete(Err(ImapNotifyWatchError::Overflow)) => {}
            state => panic!("expected Overflow, got {state:?}"),
        }
    }

    #[test]
    fn a_refused_notify_never_opens_the_watch() {
        let (mut cor, _) = watch(false, &[]);
        let mut frag = Fragmentizer::new(1 << 20);

        wants(step(&mut cor, &mut frag, None), "tag");
        written(step(&mut cor, &mut frag, Some(b"A1")));
        wants(step(&mut cor, &mut frag, None), "read");
        let reply = b"A1 NO [BADEVENT MailboxMetadataChange] Unsupported NOTIFY events.\r\n";
        match step(&mut cor, &mut frag, Some(reply)) {
            ImapCoroutineState::Complete(Err(ImapNotifyWatchError::Notify(
                ImapNotifySetError::BadEvent { .. },
            ))) => {}
            state => panic!("expected BadEvent, got {state:?}"),
        }
        assert!(!cor.opened());
    }

    #[test]
    fn condstore_is_enabled_before_the_notify() {
        let (mut cor, _) = watch(false, CONDSTORE);
        let mut frag = Fragmentizer::new(1 << 20);

        let enable = b"* ENABLED CONDSTORE\r\nA0 OK enabled\r\n";
        notifying(&mut cor, &mut frag, Some(enable), b"A1 OK NOTIFY done\r\n");
        assert!(cor.condstore());
    }

    #[test]
    fn a_refused_enable_ends_the_watch() {
        let (mut cor, _) = watch(false, CONDSTORE);
        let mut frag = Fragmentizer::new(1 << 20);

        wants(step(&mut cor, &mut frag, None), "tag");
        written(step(&mut cor, &mut frag, Some(b"A0")));
        wants(step(&mut cor, &mut frag, None), "read");
        match step(&mut cor, &mut frag, Some(b"A0 BAD unknown command\r\n")) {
            ImapCoroutineState::Complete(Err(ImapNotifyWatchError::Enable(
                ImapExtensionEnableError::Bad(_),
            ))) => {}
            state => panic!("expected Enable(Bad), got {state:?}"),
        }
    }

    #[test]
    fn condstore_is_not_enabled_unless_advertised() {
        for capability in [&[][..], &[Capability::CondStore], &[Capability::Enable]] {
            let (mut cor, _) = watch(false, capability);
            let mut frag = Fragmentizer::new(1 << 20);

            idling(&mut cor, &mut frag, b"A1 OK NOTIFY done\r\n");
            assert!(!cor.condstore());
        }
    }

    #[test]
    fn disable_skips_the_enable() {
        let (mut cor, _) = watch_with(false, CONDSTORE, ImapNotifyCondstore::Disable);
        let mut frag = Fragmentizer::new(1 << 20);

        idling(&mut cor, &mut frag, b"A1 OK NOTIFY done\r\n");
        assert!(!cor.condstore());
    }

    #[test]
    fn require_fails_before_sending_when_not_advertised() {
        let (mut cor, _) = watch_with(
            false,
            &[Capability::CondStore],
            ImapNotifyCondstore::Require,
        );
        let mut frag = Fragmentizer::new(1 << 20);

        match step(&mut cor, &mut frag, None) {
            ImapCoroutineState::Complete(Err(ImapNotifyWatchError::CondstoreNotSupported)) => {}
            state => panic!("expected CondstoreNotSupported, got {state:?}"),
        }
    }

    #[test]
    fn require_enables_when_advertised() {
        let (mut cor, _) = watch_with(false, CONDSTORE, ImapNotifyCondstore::Require);
        let mut frag = Fragmentizer::new(1 << 20);

        let enable = b"* ENABLED CONDSTORE\r\nA0 OK enabled\r\n";
        notifying(&mut cor, &mut frag, Some(enable), b"A1 OK NOTIFY done\r\n");
        assert!(cor.condstore());
    }

    #[test]
    fn prefer_watches_without_condstore_when_enabled_omits_it() {
        for reply in [&b"A0 OK enabled\r\n"[..], b"* ENABLED\r\nA0 OK enabled\r\n"] {
            let (mut cor, _) = watch(false, CONDSTORE);
            let mut frag = Fragmentizer::new(1 << 20);

            notifying(&mut cor, &mut frag, Some(reply), b"A1 OK NOTIFY done\r\n");
            assert!(!cor.condstore());
        }
    }

    #[test]
    fn require_fails_when_enabled_omits_condstore() {
        let (mut cor, _) = watch_with(false, CONDSTORE, ImapNotifyCondstore::Require);
        let mut frag = Fragmentizer::new(1 << 20);

        wants(step(&mut cor, &mut frag, None), "tag");
        written(step(&mut cor, &mut frag, Some(b"A0")));
        wants(step(&mut cor, &mut frag, None), "read");
        match step(&mut cor, &mut frag, Some(b"A0 OK enabled\r\n")) {
            ImapCoroutineState::Complete(Err(ImapNotifyWatchError::CondstoreNotSupported)) => {}
            state => panic!("expected CondstoreNotSupported, got {state:?}"),
        }
        assert!(!cor.opened());
    }

    #[test]
    fn a_bye_to_the_enable_ends_the_watch() {
        let (mut cor, _) = watch(false, CONDSTORE);
        let mut frag = Fragmentizer::new(1 << 20);

        wants(step(&mut cor, &mut frag, None), "tag");
        written(step(&mut cor, &mut frag, Some(b"A0")));
        wants(step(&mut cor, &mut frag, None), "read");
        match step(&mut cor, &mut frag, Some(b"* BYE shutting down\r\n")) {
            ImapCoroutineState::Complete(Err(ImapNotifyWatchError::Enable(
                ImapExtensionEnableError::Bye(_),
            ))) => {}
            state => panic!("expected Enable(Bye), got {state:?}"),
        }
        assert!(!cor.opened());
    }
}
