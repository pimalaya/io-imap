//! IMAP single-mailbox watcher: IDLE (RFC 2177) for the wake signal,
//! EXAMINE (QRESYNC) (RFC 7162) for UID-keyed deltas, with a client-side
//! fallback for servers that do not advertise QRESYNC.
//!
//! The mailbox is opened with EXAMINE, not SELECT, so the session is
//! **read-only**: the watcher never writes (no flag changes, no expunge),
//! and it avoids SELECT's `\Recent` reset on every re-open.
//!
//! QRESYNC: <https://www.rfc-editor.org/rfc/rfc7162>
//!
//! ```text
//! EXAMINE (CONDSTORE) → UID FETCH 1:* (UID FLAGS) [seed shadow]
//!     → IDLE → EXAMINE (QRESYNC) → emit deltas → IDLE → ...
//! ```
//!
//! Without QRESYNC the server cannot report what changed, so each wake
//! re-reads the whole mailbox and the deltas are diffed locally against
//! the same shadow. The emitted events are identical; only the cost
//! differs, and it scales with the mailbox rather than with the change.
//!
//! ```text
//! EXAMINE → UID FETCH 1:* (UID FLAGS) [seed shadow]
//!     → IDLE → EXAMINE → UID FETCH 1:* (UID FLAGS) → diff
//!     → emit deltas → IDLE → ...
//! ```
//!
//! Both paths re-EXAMINE before resyncing, so a UIDVALIDITY change ends
//! the watch rather than keying deltas on UIDs that now mean something
//! else. The caller reconnects and rebaselines.
//!
//! A watch that ended on a lost connection is resumed rather than
//! rebaselined: [`ImapMailboxWatch::state`] hands out what it knew of
//! the mailbox, and a new watch given it as
//! [`ImapMailboxWatchOptions::resume_from`] starts at the resync, so
//! what changed during the outage is emitted.
//!
//! Connection is dedicated. Flip the shared [`AtomicBool`] to wind
//! down cleanly.
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
//!     codec::{fragmentizer::Fragmentizer, imap_types::core::TagGenerator},
//!     coroutine::{ImapCoroutine, ImapCoroutineState},
//!     types::response::Capability,
//!     watch::{ImapMailboxWatch, ImapMailboxWatchYield},
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negotiated, IMAP-authenticated)
//! let mut stream = TcpStream::connect("localhost:143").unwrap();
//!
//! let mut fragmentizer = Fragmentizer::new(50 * 1024 * 1024);
//! let mut buf = [0u8; 4096];
//!
//! // The server's advertised capabilities select the path: QRESYNC
//! // here, the whole-mailbox fallback when it is absent.
//! let capability = [Capability::QResync];
//! let mailbox = "INBOX".try_into().unwrap();
//! let shutdown = Arc::new(AtomicBool::new(false));
//! let opts = Default::default();
//! let mut coroutine = ImapMailboxWatch::new(&capability, mailbox, shutdown.clone(), opts);
//! let mut tags = TagGenerator::new();
//! let mut tag;
//! let mut arg = None;
//!
//! loop {
//!     match coroutine.resume(&mut fragmentizer, arg.take()) {
//!         ImapCoroutineState::Yielded(ImapMailboxWatchYield::WantsWrite(bytes)) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         ImapCoroutineState::Yielded(ImapMailboxWatchYield::WantsTag) => {
//!             tag = tags.generate();
//!             arg = Some(tag.as_ref().as_bytes());
//!         }
//!         ImapCoroutineState::Yielded(ImapMailboxWatchYield::WantsRead) => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         ImapCoroutineState::Yielded(ImapMailboxWatchYield::WantsWait) => {
//!             // Only a polling watch asks; sleep as long as you poll for.
//!         }
//!         ImapCoroutineState::Yielded(ImapMailboxWatchYield::Event(event)) => {
//!             println!("{event:?}");
//!         }
//!         ImapCoroutineState::Complete(Ok(())) => break,
//!         ImapCoroutineState::Complete(Err(err)) => panic!("{err}"),
//!     }
//! }
//! ```

use core::{
    mem,
    num::{NonZeroU32, NonZeroU64},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use alloc::{
    collections::{BTreeMap, VecDeque},
    string::String,
    sync::Arc,
    vec,
    vec::Vec,
};

use imap_codec::{
    fragmentizer::Fragmentizer,
    imap_types::{
        command::SelectParameter,
        core::{Atom, Vec1},
        extensions::enable::CapabilityEnable,
        fetch::{MacroOrMessageDataItemNames, MessageDataItem, MessageDataItemName},
        flag::{Flag, FlagFetch},
        mailbox::Mailbox,
        response::{Capability, Data},
        sequence::SequenceSet,
    },
};
use log::{debug, trace};
use thiserror::Error;

use crate::{
    coroutine::*,
    rfc2177::idle::{ImapIdle, ImapIdleError, ImapIdleOptions, ImapIdleYield},
    rfc3501::{
        examine::{ImapMailboxExamine, ImapMailboxExamineError, ImapMailboxExamineOptions},
        fetch::{ImapMessageFetch, ImapMessageFetchError, ImapMessageFetchOptions},
        select::ImapMailboxSelectData,
    },
    rfc5161::enable::{ImapExtensionEnable, ImapExtensionEnableError},
};

/// UID-keyed mailbox change emitted by the watcher.
///
/// `FlagsAdded`/`FlagsRemoved` are pre-diffed against the internal
/// shadow; each `flags` vector lists only the changed flags.
#[derive(Clone, Debug)]
pub enum ImapMailboxWatchEvent {
    /// A message appeared in the mailbox.
    EnvelopeAdded {
        /// The UID of the new message.
        uid: NonZeroU32,
        /// The FETCH items announcing the message.
        items: Vec<MessageDataItem<'static>>,
    },
    /// Flags were set on an existing message.
    FlagsAdded {
        /// The UID of the changed message.
        uid: NonZeroU32,
        /// The flags that were added.
        flags: Vec<Flag<'static>>,
    },
    /// Flags were cleared on an existing message.
    FlagsRemoved {
        /// The UID of the changed message.
        uid: NonZeroU32,
        /// The flags that were removed.
        flags: Vec<Flag<'static>>,
    },
    /// A message left the mailbox (expunged or moved away).
    EnvelopeRemoved {
        /// The UID of the removed message.
        uid: NonZeroU32,
    },
}

/// Failure causes during the mailbox watch flow.
#[derive(Debug, Error)]
pub enum ImapMailboxWatchError {
    /// The EXAMINE response carried no UIDVALIDITY, so deltas cannot be
    /// keyed safely.
    #[error("IMAP server did not return UIDVALIDITY in EXAMINE response")]
    MissingUidValidity,
    /// The EXAMINE response carried no HIGHESTMODSEQ, so there is no
    /// QRESYNC resync point.
    #[error("IMAP server did not return HIGHESTMODSEQ in EXAMINE response")]
    MissingHighestModSeq,
    /// The mailbox was recreated under the same name, so every known UID
    /// now means something else and the watch cannot continue.
    #[error("IMAP mailbox UIDVALIDITY changed from {known} to {seen}")]
    UidValidityChanged {
        /// The UIDVALIDITY the shadow was keyed on.
        known: NonZeroU32,
        /// The UIDVALIDITY the server reports now.
        seen: NonZeroU32,
    },
    /// The baseline `1:*` sequence set failed to parse.
    #[error("Invalid `1:*` sequence set: {0}")]
    InvalidSequenceSet(String),
    /// The initial or QRESYNC EXAMINE failed.
    #[error("IMAP EXAMINE error")]
    Examine(#[from] ImapMailboxExamineError),
    /// The baseline FETCH failed.
    #[error("IMAP FETCH error")]
    Fetch(#[from] ImapMessageFetchError),
    /// The IDLE wake-loop failed.
    #[error("IMAP IDLE error")]
    Idle(#[from] ImapIdleError),
    /// The ENABLE QRESYNC round failed.
    #[error("IMAP ENABLE error")]
    Enable(#[from] ImapExtensionEnableError),
}

/// What a watch knows of its mailbox, enough to resume it on another
/// connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImapMailboxWatchState {
    /// The UIDVALIDITY the UIDs are keyed on.
    pub uid_validity: NonZeroU32,
    /// The QRESYNC resync point, `0` on the whole-mailbox fallback.
    pub highest_mod_seq: u64,
    /// The flags of every known message, by UID.
    pub flags: BTreeMap<NonZeroU32, Vec<Flag<'static>>>,
}

/// Options of [`ImapMailboxWatch`].
#[derive(Clone, Debug, Default)]
pub struct ImapMailboxWatchOptions {
    /// The state of a previous watch of the same mailbox, to resume
    /// from instead of taking a new baseline.
    ///
    /// The watch then starts at the resync and emits what changed
    /// since. A mailbox recreated in between ends it with
    /// [`ImapMailboxWatchError::UidValidityChanged`].
    pub resume_from: Option<ImapMailboxWatchState>,
    /// How long an IDLE is held before it is re-issued.
    ///
    /// `None` takes io-imap's own default, which re-issues often
    /// enough to survive a NAT middle-box that drops a quiet
    /// connection. A server known to hold one open is asked less
    /// often, up to the 29 minutes RFC 2177 §3 allows. Ignored by a
    /// polling watch, which holds no IDLE.
    pub idle_timeout: Option<Duration>,
    /// Wait for the caller between two re-reads instead of holding
    /// IDLE.
    ///
    /// A polling watch yields [`ImapMailboxWatchYield::WantsWait`] and
    /// re-reads on the resume that follows, so how long it waits, and
    /// therefore how quickly it notices a change, is its driver's to
    /// decide. Off by default: a server that offers IDLE is better
    /// asked to speak first.
    pub poll: bool,
}

/// Yield variants from the mailbox watcher.
#[derive(Debug)]
pub enum ImapMailboxWatchYield {
    /// The caller resumes with the tag of the next command.
    WantsTag,
    /// The caller reads from its stream and resumes with the bytes.
    WantsRead,
    /// The caller waits as long as it means to poll for, then resumes
    /// with no input. Only a polling watch yields this.
    WantsWait,
    /// The caller writes the given bytes to its stream and resumes.
    WantsWrite(Vec<u8>),
    /// A mailbox change to consume; the watcher keeps running.
    Event(ImapMailboxWatchEvent),
}

enum State {
    EnableQresync(ImapExtensionEnable),
    ExamineInitial(ImapMailboxExamine),
    FetchBaseline(ImapMessageFetch),
    BeginIdle,
    Idle(ImapIdle),
    Waiting,
    ExamineQresync(ImapMailboxExamine),
    ExamineResync(ImapMailboxExamine),
    FetchResync(ImapMessageFetch),
    EmitDeltas,
    Terminal,
}

/// I/O-free IDLE mailbox watcher, QRESYNC-driven or whole-mailbox.
pub struct ImapMailboxWatch {
    state: State,
    opts: ImapMailboxWatchOptions,
    qresync: bool,
    shutdown: Arc<AtomicBool>,
    idle_done: Arc<AtomicBool>,
    idle_saw_data: bool,
    mailbox: Mailbox<'static>,
    uid_validity: Option<NonZeroU32>,
    highest_mod_seq: u64,
    shadow: BTreeMap<NonZeroU32, Vec<Flag<'static>>>,
    seeded: bool,
    pending: VecDeque<ImapMailboxWatchEvent>,
}

impl ImapMailboxWatch {
    /// Builds a watcher for `mailbox`, picking its path from
    /// `capability`: QRESYNC when the server advertises it, the
    /// whole-mailbox fallback otherwise.
    pub fn new(
        capability: &[Capability<'static>],
        mailbox: Mailbox<'static>,
        shutdown: Arc<AtomicBool>,
        mut opts: ImapMailboxWatchOptions,
    ) -> Self {
        let qresync = capability.contains(&Capability::QResync);
        let known = opts.resume_from.take();

        let mut watch = Self {
            state: State::Terminal,
            opts,
            qresync,
            shutdown,
            idle_done: Arc::new(AtomicBool::new(false)),
            idle_saw_data: false,
            mailbox,
            uid_validity: None,
            highest_mod_seq: 0,
            shadow: BTreeMap::new(),
            seeded: false,
            pending: VecDeque::new(),
        };

        if let Some(known) = known {
            debug!("resuming from a previous watch");
            watch.uid_validity = Some(known.uid_validity);
            watch.highest_mod_seq = known.highest_mod_seq;
            watch.shadow = known.flags;
            watch.seeded = true;
        }

        watch.state = if qresync {
            // NOTE: RFC 7162 §3.1: QRESYNC implies CONDSTORE, but pass
            // both since some servers only echo CONDSTORE in ENABLED.
            let condstore = CapabilityEnable::CondStore;
            // NOTE: QRESYNC is not in the typed enum, route via Atom.
            let qresync = CapabilityEnable::from(
                Atom::try_from("QRESYNC").expect("`QRESYNC` is a syntactically valid IMAP atom"),
            );
            let capabilities =
                Vec1::try_from(vec![condstore, qresync]).expect("two capabilities is non-empty");

            State::EnableQresync(ImapExtensionEnable::new(capabilities))
        } else {
            debug!("qresync unsupported, watching the whole mailbox");

            if watch.seeded {
                watch.resync()
            } else {
                State::ExamineInitial(ImapMailboxExamine::new(
                    watch.mailbox.clone(),
                    ImapMailboxExamineOptions::default(),
                ))
            }
        };

        watch
    }

    /// What the watch knows of its mailbox, `None` until its baseline
    /// is taken.
    ///
    /// Taken once the watch has ended, it accounts for every event it
    /// yielded, so a watch resumed from it emits what changed since.
    pub fn state(&self) -> Option<ImapMailboxWatchState> {
        if !self.seeded {
            return None;
        }

        Some(ImapMailboxWatchState {
            uid_validity: self.uid_validity?,
            highest_mod_seq: self.highest_mod_seq,
            flags: self.shadow.clone(),
        })
    }

    /// The re-read that follows a wake, whichever way the watch was
    /// woken: QRESYNC when the server can name what changed, a plain
    /// EXAMINE when the whole mailbox has to be read again.
    fn resync(&self) -> State {
        if !self.qresync {
            let examine =
                ImapMailboxExamine::new(self.mailbox.clone(), ImapMailboxExamineOptions::default());

            return State::ExamineResync(examine);
        }

        // NOTE: uid_validity is set by ExamineInitial or a resumed state.
        let uid_validity = self.uid_validity.unwrap();
        let modseq = NonZeroU64::new(self.highest_mod_seq)
            .unwrap_or_else(|| NonZeroU64::new(1).expect("1 is non-zero"));
        let parameters = vec![SelectParameter::QResync {
            uid_validity,
            mod_sequence_value: modseq,
            known_uids: None,
            seq_match_data: None,
        }];
        let examine = ImapMailboxExamine::new(
            self.mailbox.clone(),
            ImapMailboxExamineOptions { parameters },
        );

        State::ExamineQresync(examine)
    }

    /// Refuses a resync keyed on UIDs the server no longer means.
    fn check_uid_validity(
        &self,
        data: &ImapMailboxSelectData,
    ) -> Result<(), ImapMailboxWatchError> {
        let (Some(known), Some(seen)) = (self.uid_validity, data.uid_validity) else {
            return Ok(());
        };

        if known != seen {
            return Err(ImapMailboxWatchError::UidValidityChanged { known, seen });
        }

        Ok(())
    }

    /// Queues the flag events between two states of one message, and
    /// nothing when they agree.
    fn push_flag_deltas(
        &mut self,
        uid: NonZeroU32,
        old_flags: &[Flag<'static>],
        new_flags: &[Flag<'static>],
    ) {
        let added: Vec<Flag<'static>> = new_flags
            .iter()
            .filter(|f| !old_flags.contains(f))
            .cloned()
            .collect();
        let removed: Vec<Flag<'static>> = old_flags
            .iter()
            .filter(|f| !new_flags.contains(f))
            .cloned()
            .collect();

        if !added.is_empty() {
            self.pending
                .push_back(ImapMailboxWatchEvent::FlagsAdded { uid, flags: added });
        }

        if !removed.is_empty() {
            self.pending.push_back(ImapMailboxWatchEvent::FlagsRemoved {
                uid,
                flags: removed,
            });
        }
    }

    /// Diffs a whole-mailbox snapshot against the shadow, the fallback
    /// counterpart of [`Self::compute_deltas`]: absence is what reports
    /// a vanished message, since no untagged VANISHED arrives.
    fn compute_snapshot_deltas(
        &mut self,
        snapshot: BTreeMap<NonZeroU32, Vec<MessageDataItem<'static>>>,
    ) {
        let vanished: Vec<NonZeroU32> = self
            .shadow
            .keys()
            .filter(|uid| !snapshot.contains_key(uid))
            .copied()
            .collect();

        for uid in vanished {
            self.shadow.remove(&uid);
            self.pending
                .push_back(ImapMailboxWatchEvent::EnvelopeRemoved { uid });
        }

        for (uid, items) in snapshot {
            let (_uid, new_flags) = extract_uid_flags(&items);

            match self.shadow.insert(uid, new_flags.clone()) {
                None => {
                    self.pending
                        .push_back(ImapMailboxWatchEvent::EnvelopeAdded { uid, items });
                }
                Some(old_flags) => self.push_flag_deltas(uid, &old_flags, &new_flags),
            }
        }
    }

    fn compute_deltas(&mut self, data: &ImapMailboxSelectData) {
        // NOTE: walk the shadow within each range rather than the range
        // itself, whose span the server chose.
        for range in &data.vanished_earlier {
            let uids: Vec<NonZeroU32> = self
                .shadow
                .range(range.clone())
                .map(|(uid, _)| *uid)
                .collect();

            for uid in uids {
                self.shadow.remove(&uid);
                self.pending
                    .push_back(ImapMailboxWatchEvent::EnvelopeRemoved { uid });
            }
        }

        for fetch in &data.changed {
            let items_vec: Vec<MessageDataItem<'static>> =
                fetch.items.clone().into_inner().into_iter().collect();
            let (uid_opt, new_flags) = extract_uid_flags(&items_vec);
            let Some(uid) = uid_opt else {
                continue;
            };

            match self.shadow.insert(uid, new_flags.clone()) {
                None => {
                    self.pending
                        .push_back(ImapMailboxWatchEvent::EnvelopeAdded {
                            uid,
                            items: items_vec,
                        });
                }
                Some(old_flags) => self.push_flag_deltas(uid, &old_flags, &new_flags),
            }
        }
    }
}

/// Builds the `UID FETCH 1:* (UID FLAGS)` that seeds the shadow and, on
/// the fallback path, re-reads it on every wake.
///
/// By UID, since `*` as a sequence number is an error on an empty
/// mailbox (RFC 3501 §9).
fn fetch_uid_flags() -> Result<ImapMessageFetch, ImapMailboxWatchError> {
    let sequence_set: SequenceSet = "1:*"
        .try_into()
        .map_err(|_| ImapMailboxWatchError::InvalidSequenceSet("1:*".into()))?;
    let item_names = MacroOrMessageDataItemNames::MessageDataItemNames(vec![
        MessageDataItemName::Uid,
        MessageDataItemName::Flags,
    ]);
    let opts = ImapMessageFetchOptions {
        uid: true,
        ..Default::default()
    };

    Ok(ImapMessageFetch::new(sequence_set, item_names, opts))
}

impl ImapCoroutine for ImapMailboxWatch {
    type Yield = ImapMailboxWatchYield;
    type Return = Result<(), ImapMailboxWatchError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        mut arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        if self.shutdown.load(Ordering::SeqCst) {
            self.idle_done.store(true, Ordering::SeqCst);
        }

        loop {
            let state = mem::replace(&mut self.state, State::Terminal);

            match state {
                State::EnableQresync(mut enable) => match enable.resume(fragmentizer, arg.take()) {
                    ImapCoroutineState::Yielded(ImapYield::WantsTag) => {
                        self.state = State::EnableQresync(enable);
                        return ImapCoroutineState::Yielded(ImapMailboxWatchYield::WantsTag);
                    }
                    ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
                        self.state = State::EnableQresync(enable);
                        return ImapCoroutineState::Yielded(ImapMailboxWatchYield::WantsRead);
                    }
                    ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
                        self.state = State::EnableQresync(enable);
                        return ImapCoroutineState::Yielded(ImapMailboxWatchYield::WantsWrite(
                            bytes,
                        ));
                    }
                    ImapCoroutineState::Complete(Ok(enabled)) => {
                        debug!("enabled qresync");
                        trace!("{enabled:?}");

                        if self.seeded {
                            self.state = self.resync();
                            continue;
                        }

                        let parameters = vec![SelectParameter::CondStore];
                        let examine = ImapMailboxExamine::new(
                            self.mailbox.clone(),
                            ImapMailboxExamineOptions { parameters },
                        );
                        self.state = State::ExamineInitial(examine);
                    }
                    ImapCoroutineState::Complete(Err(err)) => {
                        return ImapCoroutineState::Complete(Err(err.into()));
                    }
                },

                State::ExamineInitial(mut examine) => {
                    match examine.resume(fragmentizer, arg.take()) {
                        ImapCoroutineState::Yielded(ImapYield::WantsTag) => {
                            self.state = State::ExamineInitial(examine);
                            return ImapCoroutineState::Yielded(ImapMailboxWatchYield::WantsTag);
                        }
                        ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
                            self.state = State::ExamineInitial(examine);
                            return ImapCoroutineState::Yielded(ImapMailboxWatchYield::WantsRead);
                        }
                        ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
                            self.state = State::ExamineInitial(examine);
                            return ImapCoroutineState::Yielded(ImapMailboxWatchYield::WantsWrite(
                                bytes,
                            ));
                        }
                        ImapCoroutineState::Complete(Ok(data)) => {
                            let Some(uid_validity) = data.uid_validity else {
                                return ImapCoroutineState::Complete(Err(
                                    ImapMailboxWatchError::MissingUidValidity,
                                ));
                            };

                            self.uid_validity = Some(uid_validity);
                            trace!("uid_validity: {uid_validity}");

                            if self.qresync {
                                let Some(highest_mod_seq) = data.highest_mod_seq else {
                                    return ImapCoroutineState::Complete(Err(
                                        ImapMailboxWatchError::MissingHighestModSeq,
                                    ));
                                };

                                self.highest_mod_seq = highest_mod_seq;
                                debug!("examined mailbox with condstore");
                                trace!("highest_mod_seq: {highest_mod_seq}");
                            } else {
                                debug!("examined mailbox");
                            }

                            let fetch = match fetch_uid_flags() {
                                Ok(fetch) => fetch,
                                Err(err) => return ImapCoroutineState::Complete(Err(err)),
                            };
                            self.state = State::FetchBaseline(fetch);
                        }
                        ImapCoroutineState::Complete(Err(err)) => {
                            return ImapCoroutineState::Complete(Err(err.into()));
                        }
                    }
                }

                State::FetchBaseline(mut fetch) => match fetch.resume(fragmentizer, arg.take()) {
                    ImapCoroutineState::Yielded(ImapYield::WantsTag) => {
                        self.state = State::FetchBaseline(fetch);
                        return ImapCoroutineState::Yielded(ImapMailboxWatchYield::WantsTag);
                    }
                    ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
                        self.state = State::FetchBaseline(fetch);
                        return ImapCoroutineState::Yielded(ImapMailboxWatchYield::WantsRead);
                    }
                    ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
                        self.state = State::FetchBaseline(fetch);
                        return ImapCoroutineState::Yielded(ImapMailboxWatchYield::WantsWrite(
                            bytes,
                        ));
                    }
                    ImapCoroutineState::Complete(Ok(data)) => {
                        for (_seq, items) in data {
                            let items_vec = items.into_inner();
                            if let (Some(uid), flags) = extract_uid_flags(&items_vec) {
                                self.shadow.insert(uid, flags);
                            }
                        }
                        self.seeded = true;
                        debug!("seeded baseline shadow");
                        trace!("uids: {}", self.shadow.len());
                        self.state = State::BeginIdle;
                    }
                    ImapCoroutineState::Complete(Err(err)) => {
                        return ImapCoroutineState::Complete(Err(err.into()));
                    }
                },

                State::BeginIdle => {
                    if self.shutdown.load(Ordering::SeqCst) {
                        return ImapCoroutineState::Complete(Ok(()));
                    }

                    // NOTE: waiting is an effect, so a polling watch
                    // hands the wait back to its driver rather than
                    // holding IDLE. How long to wait is the driver's,
                    // which is why nothing here names a duration.
                    if self.opts.poll {
                        self.state = State::Waiting;
                        return ImapCoroutineState::Yielded(ImapMailboxWatchYield::WantsWait);
                    }

                    self.idle_done.store(false, Ordering::SeqCst);
                    self.idle_saw_data = false;
                    let opts = ImapIdleOptions {
                        timeout: self.opts.idle_timeout,
                    };
                    let idle = ImapIdle::new(self.idle_done.clone(), opts);
                    self.state = State::Idle(idle);
                }

                State::Waiting => {
                    if self.shutdown.load(Ordering::SeqCst) {
                        return ImapCoroutineState::Complete(Ok(()));
                    }

                    self.state = self.resync();
                }

                State::Idle(mut idle) => match idle.resume(fragmentizer, arg.take()) {
                    ImapCoroutineState::Yielded(ImapIdleYield::Event(event)) => {
                        // NOTE: a keepalive such as `* OK Still here`
                        // says nothing of the mailbox.
                        let changed = event.data.iter().any(|data| {
                            matches!(
                                data,
                                Data::Exists(_)
                                    | Data::Expunge(_)
                                    | Data::Fetch { .. }
                                    | Data::Vanished { .. }
                            )
                        });

                        if changed {
                            debug!("idle saw mailbox data");
                            self.idle_saw_data = true;
                            self.idle_done.store(true, Ordering::SeqCst);
                        }

                        self.state = State::Idle(idle);
                    }
                    ImapCoroutineState::Yielded(ImapIdleYield::WantsTag) => {
                        self.state = State::Idle(idle);
                        return ImapCoroutineState::Yielded(ImapMailboxWatchYield::WantsTag);
                    }
                    ImapCoroutineState::Yielded(ImapIdleYield::WantsRead) => {
                        self.state = State::Idle(idle);
                        return ImapCoroutineState::Yielded(ImapMailboxWatchYield::WantsRead);
                    }
                    ImapCoroutineState::Yielded(ImapIdleYield::WantsWrite(bytes)) => {
                        self.state = State::Idle(idle);
                        return ImapCoroutineState::Yielded(ImapMailboxWatchYield::WantsWrite(
                            bytes,
                        ));
                    }
                    ImapCoroutineState::Complete(Ok(())) => {
                        if self.shutdown.load(Ordering::SeqCst) {
                            return ImapCoroutineState::Complete(Ok(()));
                        }

                        if self.idle_saw_data {
                            self.state = self.resync();
                        } else {
                            debug!("idle timed out with no data, restarting");
                            self.state = State::BeginIdle;
                        }
                    }
                    ImapCoroutineState::Complete(Err(err)) => {
                        return ImapCoroutineState::Complete(Err(err.into()));
                    }
                },

                State::ExamineQresync(mut examine) => {
                    match examine.resume(fragmentizer, arg.take()) {
                        ImapCoroutineState::Yielded(ImapYield::WantsTag) => {
                            self.state = State::ExamineQresync(examine);
                            return ImapCoroutineState::Yielded(ImapMailboxWatchYield::WantsTag);
                        }
                        ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
                            self.state = State::ExamineQresync(examine);
                            return ImapCoroutineState::Yielded(ImapMailboxWatchYield::WantsRead);
                        }
                        ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
                            self.state = State::ExamineQresync(examine);
                            return ImapCoroutineState::Yielded(ImapMailboxWatchYield::WantsWrite(
                                bytes,
                            ));
                        }
                        ImapCoroutineState::Complete(Ok(data)) => {
                            if let Err(err) = self.check_uid_validity(&data) {
                                return ImapCoroutineState::Complete(Err(err));
                            }

                            self.compute_deltas(&data);
                            if let Some(new_modseq) = data.highest_mod_seq {
                                self.highest_mod_seq = new_modseq;
                            }
                            self.state = State::EmitDeltas;
                        }
                        ImapCoroutineState::Complete(Err(err)) => {
                            return ImapCoroutineState::Complete(Err(err.into()));
                        }
                    }
                }

                State::ExamineResync(mut examine) => {
                    match examine.resume(fragmentizer, arg.take()) {
                        ImapCoroutineState::Yielded(ImapYield::WantsTag) => {
                            self.state = State::ExamineResync(examine);
                            return ImapCoroutineState::Yielded(ImapMailboxWatchYield::WantsTag);
                        }
                        ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
                            self.state = State::ExamineResync(examine);
                            return ImapCoroutineState::Yielded(ImapMailboxWatchYield::WantsRead);
                        }
                        ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
                            self.state = State::ExamineResync(examine);
                            return ImapCoroutineState::Yielded(ImapMailboxWatchYield::WantsWrite(
                                bytes,
                            ));
                        }
                        ImapCoroutineState::Complete(Ok(data)) => {
                            if let Err(err) = self.check_uid_validity(&data) {
                                return ImapCoroutineState::Complete(Err(err));
                            }

                            let fetch = match fetch_uid_flags() {
                                Ok(fetch) => fetch,
                                Err(err) => return ImapCoroutineState::Complete(Err(err)),
                            };
                            self.state = State::FetchResync(fetch);
                        }
                        ImapCoroutineState::Complete(Err(err)) => {
                            return ImapCoroutineState::Complete(Err(err.into()));
                        }
                    }
                }

                State::FetchResync(mut fetch) => match fetch.resume(fragmentizer, arg.take()) {
                    ImapCoroutineState::Yielded(ImapYield::WantsTag) => {
                        self.state = State::FetchResync(fetch);
                        return ImapCoroutineState::Yielded(ImapMailboxWatchYield::WantsTag);
                    }
                    ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
                        self.state = State::FetchResync(fetch);
                        return ImapCoroutineState::Yielded(ImapMailboxWatchYield::WantsRead);
                    }
                    ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
                        self.state = State::FetchResync(fetch);
                        return ImapCoroutineState::Yielded(ImapMailboxWatchYield::WantsWrite(
                            bytes,
                        ));
                    }
                    ImapCoroutineState::Complete(Ok(data)) => {
                        let mut snapshot = BTreeMap::new();

                        for (_seq, items) in data {
                            let items_vec = items.into_inner();
                            if let (Some(uid), _flags) = extract_uid_flags(&items_vec) {
                                snapshot.insert(uid, items_vec);
                            }
                        }

                        debug!("re-read the whole mailbox");
                        trace!("uids: {}", snapshot.len());
                        self.compute_snapshot_deltas(snapshot);
                        self.state = State::EmitDeltas;
                    }
                    ImapCoroutineState::Complete(Err(err)) => {
                        return ImapCoroutineState::Complete(Err(err.into()));
                    }
                },

                State::EmitDeltas => {
                    if let Some(event) = self.pending.pop_front() {
                        self.state = State::EmitDeltas;
                        return ImapCoroutineState::Yielded(ImapMailboxWatchYield::Event(event));
                    }
                    self.state = State::BeginIdle;
                }

                State::Terminal => {
                    self.state = State::Terminal;
                    return ImapCoroutineState::Complete(Ok(()));
                }
            }
        }
    }
}

/// Extract the UID and flag list from a single FETCH; preserves wire
/// order, drops non-`Flag` variants of [`FlagFetch`].
fn extract_uid_flags(
    items: &[MessageDataItem<'static>],
) -> (Option<NonZeroU32>, Vec<Flag<'static>>) {
    let mut uid = None;
    let mut flags = Vec::new();
    for item in items {
        match item {
            MessageDataItem::Uid(u) => uid = Some(*u),
            MessageDataItem::Flags(fs) => {
                flags = fs
                    .iter()
                    .filter_map(|f| match f {
                        FlagFetch::Flag(flag) => Some(flag.clone()),
                        _ => None,
                    })
                    .collect();
            }
            _ => {}
        }
    }
    (uid, flags)
}

#[cfg(test)]
mod tests {
    use core::str;

    use alloc::{borrow::ToOwned, format, string::ToString};

    use crate::watch::*;

    const UID_VALIDITY: u32 = 1700;

    #[test]
    fn vanished_range_removes_only_shadowed_uids() {
        let (mut watch, _) = watcher(&[Capability::QResync]);
        let uid = |n| NonZeroU32::new(n).expect("non-zero");

        for n in [2, 5, 9] {
            watch.shadow.insert(uid(n), Vec::new());
        }

        let whole = uid(1)..=NonZeroU32::MAX;
        let data = ImapMailboxSelectData {
            vanished_earlier: Vec::from([whole]),
            ..Default::default()
        };
        watch.compute_deltas(&data);
        assert!(watch.shadow.is_empty());

        let removed: Vec<u32> = watch
            .pending
            .iter()
            .map(|event| match event {
                ImapMailboxWatchEvent::EnvelopeRemoved { uid } => uid.get(),
                event => panic!("expected EnvelopeRemoved, got {event:?}"),
            })
            .collect();
        assert_eq!(Vec::from([2, 5, 9]), removed);
    }

    /// One scripted exchange: the fragment the next written command
    /// must contain, then the replies to feed it, `{tag}` standing for
    /// the tag the watcher chose.
    type Step<'a> = (&'a str, &'a [&'a str]);

    fn watcher(capability: &[Capability<'static>]) -> (ImapMailboxWatch, Fragmentizer) {
        watcher_with(capability, ImapMailboxWatchOptions::default())
    }

    fn watcher_with(
        capability: &[Capability<'static>],
        opts: ImapMailboxWatchOptions,
    ) -> (ImapMailboxWatch, Fragmentizer) {
        let watch = ImapMailboxWatch::new(
            capability,
            "INBOX".try_into().expect("valid mailbox"),
            Arc::new(AtomicBool::new(false)),
            opts,
        );

        (watch, Fragmentizer::new(50 * 1024 * 1024))
    }

    fn first_word(line: &str) -> &str {
        line.split_whitespace()
            .next()
            .expect("first whitespace-separated token")
    }

    /// Plays `steps` against the watcher and collects what it emitted,
    /// stopping at the first command the script does not answer.
    fn drive(
        cor: &mut ImapMailboxWatch,
        frag: &mut Fragmentizer,
        steps: &[Step],
    ) -> Result<Vec<ImapMailboxWatchEvent>, ImapMailboxWatchError> {
        let mut events = Vec::new();
        let mut replies: VecDeque<String> = VecDeque::new();
        let mut tag = String::new();
        let mut next = 0;
        let mut issued = 0;
        let mut arg: Option<Vec<u8>> = None;

        loop {
            match cor.resume(frag, arg.take().as_deref()) {
                ImapCoroutineState::Yielded(ImapMailboxWatchYield::WantsTag) => {
                    issued += 1;
                    arg = Some(format!("A{issued}").into_bytes());
                }
                ImapCoroutineState::Yielded(ImapMailboxWatchYield::WantsWrite(bytes)) => {
                    let line = str::from_utf8(&bytes).expect("utf8 command").to_string();

                    let Some((expected, scripted)) = steps.get(next) else {
                        return Ok(events);
                    };

                    assert!(line.contains(expected), "expected {expected}, wrote {line}");
                    next += 1;

                    // NOTE: DONE closes the IDLE the server still owes a
                    // tagged reply to, so it carries no tag of its own.
                    if !line.starts_with("DONE") {
                        tag = first_word(&line).to_owned();
                    }

                    replies.extend(scripted.iter().map(|reply| reply.replace("{tag}", &tag)));
                }
                ImapCoroutineState::Yielded(ImapMailboxWatchYield::WantsRead) => {
                    let reply = replies
                        .pop_front()
                        .expect("the script owes a reply to every read");
                    arg = Some(reply.into_bytes());
                }
                ImapCoroutineState::Yielded(ImapMailboxWatchYield::Event(event)) => {
                    events.push(event);
                }
                // NOTE: the driver is what waits, and a test has
                // nothing to wait for.
                ImapCoroutineState::Yielded(ImapMailboxWatchYield::WantsWait) => {}
                ImapCoroutineState::Complete(Ok(())) => panic!("the watch stopped early"),
                ImapCoroutineState::Complete(Err(err)) => return Err(err),
            }
        }
    }

    /// The very first command the watcher writes, which is what its
    /// path shows.
    fn first_command(cor: &mut ImapMailboxWatch, frag: &mut Fragmentizer) -> String {
        match cor.resume(frag, None) {
            ImapCoroutineState::Yielded(ImapMailboxWatchYield::WantsTag) => {}
            state => panic!("expected WantsTag, got {state:?}"),
        }

        match cor.resume(frag, Some(b"A1")) {
            ImapCoroutineState::Yielded(ImapMailboxWatchYield::WantsWrite(bytes)) => {
                str::from_utf8(&bytes).expect("utf8 command").to_string()
            }
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    /// The EXAMINE reply of a mailbox that has never been recreated.
    fn examined(uid_validity: u32) -> String {
        format!(
            "* 2 EXISTS\r\n\
             * OK [UIDVALIDITY {uid_validity}] uid validity\r\n\
             {{tag}} OK [READ-ONLY] EXAMINE completed\r\n",
        )
    }

    /// A `FETCH 1:* (UID FLAGS)` reply, one message per UID and flags
    /// pair.
    fn fetched(messages: &[(u32, &str)]) -> String {
        let mut reply = String::new();

        for (seq, (uid, flags)) in messages.iter().enumerate() {
            reply.push_str(&format!(
                "* {} FETCH (UID {uid} FLAGS ({flags}))\r\n",
                seq + 1
            ));
        }

        reply.push_str("{tag} OK FETCH completed\r\n");
        reply
    }

    #[test]
    fn qresync_capability_enables_it_first() {
        let (mut watch, mut frag) = watcher(&[Capability::QResync]);
        let line = first_command(&mut watch, &mut frag);

        assert!(line.contains("ENABLE"), "wrote {line}");
    }

    #[test]
    fn missing_qresync_examines_straight_away() {
        let (mut watch, mut frag) = watcher(&[]);
        let line = first_command(&mut watch, &mut frag);

        assert!(line.contains("EXAMINE INBOX"), "wrote {line}");
        assert!(!line.contains("ENABLE"), "wrote {line}");
        assert!(!line.contains("CONDSTORE"), "wrote {line}");
    }

    #[test]
    fn fallback_diffs_the_whole_mailbox_on_every_wake() {
        let (mut watch, mut frag) = watcher(&[]);
        let baseline = fetched(&[(1, ""), (2, "")]);
        let resynced = fetched(&[(2, "\\Seen"), (3, "")]);
        let steps: &[Step] = &[
            ("EXAMINE INBOX", &[&examined(UID_VALIDITY)]),
            ("FETCH 1:* (UID FLAGS)", &[&baseline]),
            ("IDLE", &["+ idling\r\n", "* 3 EXISTS\r\n"]),
            ("DONE", &["{tag} OK IDLE terminated\r\n"]),
            ("EXAMINE INBOX", &[&examined(UID_VALIDITY)]),
            ("FETCH 1:* (UID FLAGS)", &[&resynced]),
        ];

        let events = drive(&mut watch, &mut frag, steps).expect("watch running");
        assert_eq!(3, events.len(), "got {events:?}");

        // NOTE: no VANISHED arrives without QRESYNC, so a UID missing
        // from the snapshot is what reports the removal.
        let ImapMailboxWatchEvent::EnvelopeRemoved { uid } = &events[0] else {
            panic!("expected EnvelopeRemoved, got {:?}", events[0]);
        };
        assert_eq!(1, uid.get());

        let ImapMailboxWatchEvent::FlagsAdded { uid, flags } = &events[1] else {
            panic!("expected FlagsAdded, got {:?}", events[1]);
        };
        assert_eq!(2, uid.get());
        assert_eq!(&vec![Flag::Seen], flags);

        let ImapMailboxWatchEvent::EnvelopeAdded { uid, .. } = &events[2] else {
            panic!("expected EnvelopeAdded, got {:?}", events[2]);
        };
        assert_eq!(3, uid.get());
    }

    #[test]
    fn fallback_reports_nothing_when_the_mailbox_is_unchanged() {
        let (mut watch, mut frag) = watcher(&[]);
        let snapshot = fetched(&[(1, "\\Seen")]);
        let steps: &[Step] = &[
            ("EXAMINE INBOX", &[&examined(UID_VALIDITY)]),
            ("FETCH 1:* (UID FLAGS)", &[&snapshot]),
            ("IDLE", &["+ idling\r\n", "* 1 EXISTS\r\n"]),
            ("DONE", &["{tag} OK IDLE terminated\r\n"]),
            ("EXAMINE INBOX", &[&examined(UID_VALIDITY)]),
            ("FETCH 1:* (UID FLAGS)", &[&snapshot]),
        ];

        let events = drive(&mut watch, &mut frag, steps).expect("watch running");
        assert!(events.is_empty(), "got {events:?}");
    }

    /// A polling watch never sends IDLE: it asks its driver to wait
    /// and re-reads on the resume that follows, which is what lets a
    /// caller watch a server whose IDLE cannot be trusted.
    #[test]
    fn a_polling_watch_re_reads_instead_of_idling() {
        let opts = ImapMailboxWatchOptions {
            poll: true,
            ..Default::default()
        };
        let (mut watch, mut frag) = watcher_with(&[], opts);
        let baseline = fetched(&[(1, "")]);
        let resynced = fetched(&[(1, "\\Seen")]);
        let steps: &[Step] = &[
            ("EXAMINE INBOX", &[&examined(UID_VALIDITY)]),
            ("FETCH 1:* (UID FLAGS)", &[&baseline]),
            ("EXAMINE INBOX", &[&examined(UID_VALIDITY)]),
            ("FETCH 1:* (UID FLAGS)", &[&resynced]),
        ];

        let events = drive(&mut watch, &mut frag, steps).expect("watch running");

        assert_eq!(1, events.len(), "got {events:?}");
        let ImapMailboxWatchEvent::FlagsAdded { uid, flags } = &events[0] else {
            panic!("expected FlagsAdded, got {:?}", events[0]);
        };
        assert_eq!(1, uid.get());
        assert_eq!(&vec![Flag::Seen], flags);
    }

    #[test]
    fn the_baseline_is_fetched_by_uid() {
        let (mut watch, mut frag) = watcher(&[]);
        let baseline = fetched(&[]);
        let steps: &[Step] = &[
            ("EXAMINE INBOX", &[&examined(UID_VALIDITY)]),
            ("UID FETCH 1:* (UID FLAGS)", &[&baseline]),
        ];

        let events = drive(&mut watch, &mut frag, steps).expect("watch running");
        assert!(events.is_empty(), "got {events:?}");
    }

    #[test]
    fn the_state_follows_the_baseline() {
        let (mut watch, mut frag) = watcher(&[]);
        assert_eq!(None, watch.state());

        let baseline = fetched(&[(1, "\\Seen")]);
        let steps: &[Step] = &[
            ("EXAMINE INBOX", &[&examined(UID_VALIDITY)]),
            ("UID FETCH 1:* (UID FLAGS)", &[&baseline]),
        ];
        drive(&mut watch, &mut frag, steps).expect("watch running");

        let state = watch.state().expect("baseline taken");
        assert_eq!(known(0, &[(1, vec![Flag::Seen])]), state);
    }

    #[test]
    fn a_resumed_fallback_watch_emits_what_changed_meanwhile() {
        let opts = ImapMailboxWatchOptions {
            resume_from: Some(known(0, &[(1, Vec::new()), (2, Vec::new())])),
            ..Default::default()
        };
        let (mut watch, mut frag) = watcher_with(&[], opts);
        let resynced = fetched(&[(2, "\\Seen"), (3, "")]);
        let steps: &[Step] = &[
            ("EXAMINE INBOX", &[&examined(UID_VALIDITY)]),
            ("UID FETCH 1:* (UID FLAGS)", &[&resynced]),
        ];

        let events = drive(&mut watch, &mut frag, steps).expect("watch running");
        assert_eq!(3, events.len(), "got {events:?}");
        assert!(matches!(
            &events[0],
            ImapMailboxWatchEvent::EnvelopeRemoved { uid } if uid.get() == 1
        ));
        assert!(matches!(
            &events[1],
            ImapMailboxWatchEvent::FlagsAdded { uid, .. } if uid.get() == 2
        ));
        assert!(matches!(
            &events[2],
            ImapMailboxWatchEvent::EnvelopeAdded { uid, .. } if uid.get() == 3
        ));
    }

    #[test]
    fn a_resumed_qresync_watch_starts_at_the_resync() {
        let opts = ImapMailboxWatchOptions {
            resume_from: Some(known(42, &[(1, Vec::new()), (2, Vec::new())])),
            ..Default::default()
        };
        let (mut watch, mut frag) = watcher_with(&[Capability::QResync], opts);
        let resynced = format!(
            "* 2 EXISTS\r\n\
             * OK [UIDVALIDITY {UID_VALIDITY}] uid validity\r\n\
             * OK [HIGHESTMODSEQ 50] modseq\r\n\
             * VANISHED (EARLIER) 1\r\n\
             * 2 FETCH (UID 3 FLAGS () MODSEQ (50))\r\n\
             {{tag}} OK [READ-ONLY] EXAMINE completed\r\n",
        );
        let steps: &[Step] = &[
            ("ENABLE", &["* ENABLED QRESYNC\r\n{tag} OK enabled\r\n"]),
            ("EXAMINE INBOX (QRESYNC (1700 42))", &[&resynced]),
        ];

        let events = drive(&mut watch, &mut frag, steps).expect("watch running");
        assert_eq!(2, events.len(), "got {events:?}");
        assert!(matches!(
            &events[0],
            ImapMailboxWatchEvent::EnvelopeRemoved { uid } if uid.get() == 1
        ));
        assert!(matches!(
            &events[1],
            ImapMailboxWatchEvent::EnvelopeAdded { uid, .. } if uid.get() == 3
        ));

        let state = watch.state().expect("state kept");
        assert_eq!(known(50, &[(2, Vec::new()), (3, Vec::new())]), state);
    }

    fn known(highest_mod_seq: u64, flags: &[(u32, Vec<Flag<'static>>)]) -> ImapMailboxWatchState {
        let flags = flags.iter().cloned();
        let flags = flags.map(|(uid, flags)| (NonZeroU32::new(uid).expect("non-zero"), flags));

        ImapMailboxWatchState {
            uid_validity: NonZeroU32::new(UID_VALIDITY).expect("non-zero"),
            highest_mod_seq,
            flags: flags.collect(),
        }
    }

    #[cfg(feature = "client")]
    #[test]
    fn data_read_while_an_idle_is_refreshed_wakes_the_watch() {
        let opts = ImapMailboxWatchOptions {
            idle_timeout: Some(Duration::ZERO),
            ..Default::default()
        };
        let (mut watch, mut frag) = watcher_with(&[], opts);
        let baseline = fetched(&[(1, "")]);
        let resynced = fetched(&[(1, ""), (2, "")]);
        let steps: &[Step] = &[
            ("EXAMINE INBOX", &[&examined(UID_VALIDITY)]),
            ("UID FETCH 1:* (UID FLAGS)", &[&baseline]),
            ("IDLE", &["+ idling\r\n"]),
            ("DONE", &["* 2 EXISTS\r\n{tag} OK IDLE terminated\r\n"]),
            ("EXAMINE INBOX", &[&examined(UID_VALIDITY)]),
            ("UID FETCH 1:* (UID FLAGS)", &[&resynced]),
        ];

        let events = drive(&mut watch, &mut frag, steps).expect("watch running");
        assert_eq!(1, events.len(), "got {events:?}");
        assert!(matches!(
            &events[0],
            ImapMailboxWatchEvent::EnvelopeAdded { uid, .. } if uid.get() == 2
        ));
    }

    #[test]
    fn a_keepalive_does_not_wake_the_watch() {
        let (mut watch, mut frag) = watcher(&[]);
        let mut replies = VecDeque::from([
            examined(UID_VALIDITY),
            fetched(&[(1, "")]),
            "+ idling\r\n".to_string(),
            "* OK Still here\r\n".to_string(),
        ]);
        let mut written = Vec::new();
        let mut issued = 0;
        let mut arg: Option<Vec<u8>> = None;

        loop {
            match watch.resume(&mut frag, arg.take().as_deref()) {
                ImapCoroutineState::Yielded(ImapMailboxWatchYield::WantsTag) => {
                    issued += 1;
                    arg = Some(format!("A{issued}").into_bytes());
                }
                ImapCoroutineState::Yielded(ImapMailboxWatchYield::WantsWrite(bytes)) => {
                    written.push(str::from_utf8(&bytes).expect("utf8 command").to_string());
                }
                ImapCoroutineState::Yielded(ImapMailboxWatchYield::WantsRead) => {
                    let Some(reply) = replies.pop_front() else {
                        break;
                    };
                    arg = Some(reply.replace("{tag}", &format!("A{issued}")).into_bytes());
                }
                state => panic!("expected an I/O request, got {state:?}"),
            }
        }

        assert_eq!("A3 IDLE\r\n", written.last().expect("commands written"));
    }

    #[test]
    fn a_recreated_mailbox_ends_the_watch() {
        let (mut watch, mut frag) = watcher(&[]);
        let baseline = fetched(&[(1, "")]);
        let steps: &[Step] = &[
            ("EXAMINE INBOX", &[&examined(UID_VALIDITY)]),
            ("FETCH 1:* (UID FLAGS)", &[&baseline]),
            ("IDLE", &["+ idling\r\n", "* 1 EXPUNGE\r\n"]),
            ("DONE", &["{tag} OK IDLE terminated\r\n"]),
            ("EXAMINE INBOX", &[&examined(UID_VALIDITY + 1)]),
        ];

        let err = drive(&mut watch, &mut frag, steps).expect_err("uid validity changed");
        let ImapMailboxWatchError::UidValidityChanged { known, seen } = err else {
            panic!("expected UidValidityChanged, got {err:?}");
        };
        assert_eq!(UID_VALIDITY, known.get());
        assert_eq!(UID_VALIDITY + 1, seen.get());
    }
}
