//! I/O-free coroutine watching a single IMAP mailbox for changes
//! using IDLE (RFC 2177) for the wake signal and SELECT (QRESYNC)
//! (RFC 7162) for the deltas.
//!
//! Why both: IDLE alone delivers untagged `EXISTS` / `EXPUNGE` /
//! `FETCH` responses, but they use sequence numbers that shift as
//! messages disappear and they only give a count (not UIDs) on
//! arrival. QRESYNC alone misses the wake signal: it tells you what
//! changed since the last checkpoint but nothing about *when* it
//! changed. Composed, the pair gives a reliable UID-keyed change
//! stream:
//!
//! ```text
//! SELECT (initial, CONDSTORE)
//!     ↓ HIGHESTMODSEQ + UIDVALIDITY
//! FETCH 1:* (UID FLAGS)
//!     ↓ seed shadow (no events emitted)
//! IDLE ──┐
//!        │ on any untagged response: send DONE
//!        ↓
//! SELECT (QRESYNC ...)
//!     ↓ VANISHED + implicit FETCHes from the server
//! emit events ──► IDLE ──► …
//! ```
//!
//! Mailbox stays SELECTed for the lifetime of the coroutine; the
//! connection is dedicated. Shutdown is cooperative: flip the
//! [`AtomicBool`] handed to [`ImapMailboxWatch::new`] and the
//! coroutine winds the running IDLE down at its next loop iteration,
//! completing with `Ok(())`.

use core::{
    mem,
    num::{NonZeroU32, NonZeroU64},
    sync::atomic::{AtomicBool, Ordering},
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
        response::Capability,
        sequence::SequenceSet,
    },
};
use log::trace;
use thiserror::Error;

use crate::{
    coroutine::*,
    rfc2177::idle::{ImapIdle, ImapIdleError, ImapIdleOptions, ImapIdleYield},
    rfc3501::{
        fetch::{ImapMessageFetch, ImapMessageFetchError, ImapMessageFetchOptions},
        select::{ImapMailboxSelect, ImapMailboxSelectError, SelectData},
    },
    rfc5161::enable::{ImapExtensionEnable, ImapExtensionEnableError},
};

/// Watch event emitted by [`ImapMailboxWatch::resume`].
///
/// `EnvelopeAdded` carries the raw FETCH item list so callers stay in
/// charge of how they parse it (full envelope, flags-only, …).
/// `FlagsAdded` / `FlagsRemoved` are pre-diffed against the
/// coroutine's internal shadow; each `flags` vector contains only the
/// wire-level flags that actually changed in this iteration. Order
/// inside the vector follows the server's response order.
#[derive(Clone, Debug)]
pub enum ImapMailboxWatchEvent {
    EnvelopeAdded {
        uid: NonZeroU32,
        items: Vec<MessageDataItem<'static>>,
    },
    FlagsAdded {
        uid: NonZeroU32,
        flags: Vec<Flag<'static>>,
    },
    FlagsRemoved {
        uid: NonZeroU32,
        flags: Vec<Flag<'static>>,
    },
    EnvelopeRemoved {
        uid: NonZeroU32,
    },
}

/// Errors that can occur during the coroutine progression.
#[derive(Debug, Error)]
pub enum ImapMailboxWatchError {
    #[error("IMAP server does not advertise QRESYNC")]
    QresyncUnsupported,
    #[error("IMAP server did not return UIDVALIDITY in SELECT response")]
    MissingUidValidity,
    #[error("IMAP server did not return HIGHESTMODSEQ in SELECT response")]
    MissingHighestModSeq,
    #[error("Invalid `1:*` sequence set: {0}")]
    InvalidSequenceSet(String),
    #[error("IMAP SELECT error")]
    Select(#[from] ImapMailboxSelectError),
    #[error("IMAP FETCH error")]
    Fetch(#[from] ImapMessageFetchError),
    #[error("IMAP IDLE error")]
    Idle(#[from] ImapIdleError),
    #[error("IMAP ENABLE error")]
    Enable(#[from] ImapExtensionEnableError),
}

/// Per-coroutine Yield: socket I/O step requests on one axis, domain
/// events on the other. The driver dispatches on the variant: I/O
/// variants pump the IMAP socket; [`Self::Event`] is delivered to the
/// caller (callback / channel / async stream).
#[derive(Debug)]
pub enum ImapMailboxWatchYield {
    /// Socket: read more bytes and feed them back on the next
    /// resume.
    WantsRead,
    /// Socket: write these bytes; the next resume typically takes
    /// `None`.
    WantsWrite(Vec<u8>),
    /// Domain: one pre-diffed delta computed from the inner QRESYNC
    /// pull.
    Event(ImapMailboxWatchEvent),
}

enum State {
    /// ENABLE CONDSTORE QRESYNC — RFC 7162 §3.1 requires this once
    /// per session before any `SELECT (QRESYNC …)` parameter is
    /// allowed. Some servers (Dovecot included) silently accept the
    /// missing ENABLE and fall through to plain SELECT semantics;
    /// others (Cyrus, the test server that surfaced this) hard-reject
    /// the SELECT with `BAD QRESYNC not enabled`. Sending ENABLE
    /// unconditionally is correct against both.
    EnableQresync(ImapExtensionEnable),
    /// SELECT (CONDSTORE) — capture UIDVALIDITY + HIGHESTMODSEQ.
    SelectInitial(ImapMailboxSelect),
    /// FETCH 1:* (UID FLAGS) — seed the in-memory flag shadow.
    FetchBaseline(ImapMessageFetch),
    /// Construct a fresh ImapIdle and transition to Idle.
    BeginIdle,
    /// IDLE in progress.
    Idle(ImapIdle),
    /// SELECT (QRESYNC ...) — pull the delta since the last
    /// HIGHESTMODSEQ checkpoint.
    SelectQresync(ImapMailboxSelect),
    /// Drain `pending` one event at a time, yielding each as
    /// [`ImapMailboxWatchYield::Event`]. When empty, transition back
    /// to `BeginIdle`.
    EmitDeltas,
    /// Terminal state.
    Terminal,
}

/// I/O-free IDLE+QRESYNC mailbox watcher.
pub struct ImapMailboxWatch {
    state: State,
    /// External shutdown signal, shared with the caller. Flipping it
    /// asks the coroutine to wind down at its next loop iteration.
    shutdown: Arc<AtomicBool>,
    /// Inner signal handed to each fresh [`ImapIdle`]. Always cleared
    /// before a new IDLE starts; set by the watcher itself on
    /// untagged-response arrival (to trigger a QRESYNC pull) and on
    /// shutdown propagation.
    idle_done: Arc<AtomicBool>,
    /// Whether the current IDLE has seen at least one untagged
    /// response. Decides whether to pull a QRESYNC delta or just
    /// re-enter IDLE after the current one ends.
    idle_saw_data: bool,
    mailbox: Mailbox<'static>,
    uid_validity: Option<NonZeroU32>,
    highest_mod_seq: u64,
    /// UID → flags snapshot maintained across QRESYNC iterations,
    /// used to diff incoming FETCH responses into `FlagsAdded` /
    /// `FlagsRemoved` deltas and to spot first-time-seen UIDs.
    shadow: BTreeMap<NonZeroU32, Vec<Flag<'static>>>,
    /// Events ready to be drained as `Event(...)` yields.
    pending: VecDeque<ImapMailboxWatchEvent>,
}

impl ImapMailboxWatch {
    /// Creates a new coroutine targeting `mailbox`. `shutdown` is
    /// shared with the caller; when flipped, the running IDLE winds
    /// down cleanly and the next [`ImapMailboxWatch::resume`]
    /// completes with `Ok(())`.
    ///
    /// Errors with [`ImapMailboxWatchError::QresyncUnsupported`] when
    /// `capability` does not advertise `QRESYNC`. Run `CAPABILITY` (or
    /// `LOGIN` / `AUTHENTICATE` with `ensure_capabilities`) before
    /// calling this constructor.
    pub fn new(
        capability: &[Capability<'static>],
        mailbox: Mailbox<'static>,
        shutdown: Arc<AtomicBool>,
    ) -> Result<Self, ImapMailboxWatchError> {
        if !capability.contains(&Capability::QResync) {
            return Err(ImapMailboxWatchError::QresyncUnsupported);
        }

        // RFC 7162 §3.1: enabling QRESYNC implies CONDSTORE, but we
        // pass both explicitly so a server reporting only CONDSTORE
        // in the `ENABLED` reply doesn't surprise us.
        let condstore = CapabilityEnable::CondStore;
        // `CapabilityEnable::from(Atom)` falls through to `Other(_)`
        // for any token the type doesn't recognise (QRESYNC included).
        let qresync = CapabilityEnable::from(
            Atom::try_from("QRESYNC").expect("`QRESYNC` is a syntactically valid IMAP atom"),
        );
        let capabilities =
            Vec1::try_from(vec![condstore, qresync]).expect("two capabilities is non-empty");
        let enable = ImapExtensionEnable::new(capabilities);

        Ok(Self {
            state: State::EnableQresync(enable),
            shutdown,
            idle_done: Arc::new(AtomicBool::new(false)),
            idle_saw_data: false,
            mailbox,
            uid_validity: None,
            highest_mod_seq: 0,
            shadow: BTreeMap::new(),
            pending: VecDeque::new(),
        })
    }

    fn compute_deltas(&mut self, data: &SelectData) {
        for uid in &data.vanished_earlier {
            if self.shadow.remove(uid).is_some() {
                self.pending
                    .push_back(ImapMailboxWatchEvent::EnvelopeRemoved { uid: *uid });
            }
        }

        for fetch in &data.changed {
            let items_vec: Vec<MessageDataItem<'static>> =
                fetch.items.clone().into_inner().into_iter().collect();
            let (uid_opt, new_flags) = extract_uid_flags(&items_vec);
            let Some(uid) = uid_opt else {
                continue;
            };

            match self.shadow.get(&uid).cloned() {
                None => {
                    self.shadow.insert(uid, new_flags);
                    self.pending
                        .push_back(ImapMailboxWatchEvent::EnvelopeAdded {
                            uid,
                            items: items_vec,
                        });
                }
                Some(old_flags) => {
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
                    self.shadow.insert(uid, new_flags);
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
            }
        }
    }
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
                        trace!("watch: ENABLE OK ({enabled:?})");
                        let parameters = vec![SelectParameter::CondStore];
                        let select =
                            ImapMailboxSelect::with_parameters(self.mailbox.clone(), parameters);
                        self.state = State::SelectInitial(select);
                    }
                    ImapCoroutineState::Complete(Err(err)) => {
                        return ImapCoroutineState::Complete(Err(err.into()));
                    }
                },

                State::SelectInitial(mut select) => match select.resume(fragmentizer, arg.take()) {
                    ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
                        self.state = State::SelectInitial(select);
                        return ImapCoroutineState::Yielded(ImapMailboxWatchYield::WantsRead);
                    }
                    ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
                        self.state = State::SelectInitial(select);
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
                        let Some(highest_mod_seq) = data.highest_mod_seq else {
                            return ImapCoroutineState::Complete(Err(
                                ImapMailboxWatchError::MissingHighestModSeq,
                            ));
                        };

                        self.uid_validity = Some(uid_validity);
                        self.highest_mod_seq = highest_mod_seq;
                        trace!(
                            "watch: SELECT OK uidvalidity={} highestmodseq={}",
                            uid_validity.get(),
                            highest_mod_seq,
                        );

                        let sequence_set: SequenceSet = match "1:*".try_into() {
                            Ok(s) => s,
                            Err(_) => {
                                return ImapCoroutineState::Complete(Err(
                                    ImapMailboxWatchError::InvalidSequenceSet("1:*".into()),
                                ));
                            }
                        };
                        let item_names = MacroOrMessageDataItemNames::MessageDataItemNames(vec![
                            MessageDataItemName::Uid,
                            MessageDataItemName::Flags,
                        ]);
                        let fetch = ImapMessageFetch::new(
                            sequence_set,
                            item_names,
                            ImapMessageFetchOptions::default(),
                        );
                        self.state = State::FetchBaseline(fetch);
                    }
                    ImapCoroutineState::Complete(Err(err)) => {
                        return ImapCoroutineState::Complete(Err(err.into()));
                    }
                },

                State::FetchBaseline(mut fetch) => match fetch.resume(fragmentizer, arg.take()) {
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
                        trace!(
                            "watch: baseline shadow seeded with {} uids",
                            self.shadow.len(),
                        );
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

                    self.idle_done.store(false, Ordering::SeqCst);
                    self.idle_saw_data = false;
                    let idle = ImapIdle::new(self.idle_done.clone(), ImapIdleOptions::default());
                    self.state = State::Idle(idle);
                }

                State::Idle(mut idle) => match idle.resume(fragmentizer, arg.take()) {
                    ImapCoroutineState::Yielded(ImapIdleYield::Event(_)) => {
                        trace!("watch: IDLE saw untagged data");
                        self.idle_saw_data = true;
                        self.idle_done.store(true, Ordering::SeqCst);
                        self.state = State::Idle(idle);
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
                            // SAFETY: uid_validity is set by SelectInitial
                            let uid_validity = self.uid_validity.unwrap();
                            let modseq = NonZeroU64::new(self.highest_mod_seq)
                                .unwrap_or_else(|| NonZeroU64::new(1).expect("1 is non-zero"));
                            let parameters = vec![SelectParameter::QResync {
                                uid_validity,
                                mod_sequence_value: modseq,
                                known_uids: None,
                                seq_match_data: None,
                            }];
                            let select = ImapMailboxSelect::with_parameters(
                                self.mailbox.clone(),
                                parameters,
                            );
                            self.state = State::SelectQresync(select);
                        } else {
                            trace!("watch: IDLE timed out with no data, restarting");
                            self.state = State::BeginIdle;
                        }
                    }
                    ImapCoroutineState::Complete(Err(err)) => {
                        return ImapCoroutineState::Complete(Err(err.into()));
                    }
                },

                State::SelectQresync(mut select) => match select.resume(fragmentizer, arg.take()) {
                    ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
                        self.state = State::SelectQresync(select);
                        return ImapCoroutineState::Yielded(ImapMailboxWatchYield::WantsRead);
                    }
                    ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
                        self.state = State::SelectQresync(select);
                        return ImapCoroutineState::Yielded(ImapMailboxWatchYield::WantsWrite(
                            bytes,
                        ));
                    }
                    ImapCoroutineState::Complete(Ok(data)) => {
                        self.compute_deltas(&data);
                        if let Some(new_modseq) = data.highest_mod_seq {
                            self.highest_mod_seq = new_modseq;
                        }
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

/// Extracts the UID and the flag list from a single FETCH response.
/// FETCH items that aren't `UID` / `FLAGS` are ignored; only
/// `FlagFetch::Flag` variants are retained (other variants are
/// protocol noise for our purposes). The flag list preserves the
/// server's wire order.
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
