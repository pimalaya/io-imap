//! IMAP single-mailbox watcher: IDLE (RFC 2177) for the wake signal,
//! SELECT (QRESYNC) (RFC 7162) for UID-keyed deltas.
//!
//! QRESYNC: <https://www.rfc-editor.org/rfc/rfc7162>
//!
//! ```text
//! SELECT (CONDSTORE) → FETCH 1:* (UID FLAGS) [seed shadow]
//!     → IDLE → SELECT (QRESYNC) → emit deltas → IDLE → ...
//! ```
//!
//! Connection is dedicated. Flip the shared [`AtomicBool`] to wind
//! down cleanly.

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
        select::{ImapMailboxSelect, ImapMailboxSelectError, ImapMailboxSelectOptions, SelectData},
    },
    rfc5161::enable::{ImapExtensionEnable, ImapExtensionEnableError},
};

/// `FlagsAdded`/`FlagsRemoved` are pre-diffed against the internal
/// shadow; each `flags` vector lists only the changed flags.
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

/// Failure causes during the mailbox watch flow.
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

/// Yield variants from the mailbox watcher.
#[derive(Debug)]
pub enum ImapMailboxWatchYield {
    WantsRead,
    WantsWrite(Vec<u8>),
    Event(ImapMailboxWatchEvent),
}

enum State {
    EnableQresync(ImapExtensionEnable),
    SelectInitial(ImapMailboxSelect),
    FetchBaseline(ImapMessageFetch),
    BeginIdle,
    Idle(ImapIdle),
    SelectQresync(ImapMailboxSelect),
    EmitDeltas,
    Terminal,
}

/// I/O-free IDLE+QRESYNC mailbox watcher.
pub struct ImapMailboxWatch {
    state: State,
    shutdown: Arc<AtomicBool>,
    idle_done: Arc<AtomicBool>,
    idle_saw_data: bool,
    mailbox: Mailbox<'static>,
    uid_validity: Option<NonZeroU32>,
    highest_mod_seq: u64,
    shadow: BTreeMap<NonZeroU32, Vec<Flag<'static>>>,
    pending: VecDeque<ImapMailboxWatchEvent>,
}

impl ImapMailboxWatch {
    /// Errors with `QresyncUnsupported` when `capability` lacks QRESYNC.
    pub fn new(
        capability: &[Capability<'static>],
        mailbox: Mailbox<'static>,
        shutdown: Arc<AtomicBool>,
    ) -> Result<Self, ImapMailboxWatchError> {
        if !capability.contains(&Capability::QResync) {
            return Err(ImapMailboxWatchError::QresyncUnsupported);
        }

        // NOTE: RFC 7162 §3.1 — QRESYNC implies CONDSTORE, but pass
        // both since some servers only echo CONDSTORE in ENABLED.
        let condstore = CapabilityEnable::CondStore;
        // NOTE: QRESYNC is not in the typed enum, route via Atom.
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
                        let select = ImapMailboxSelect::new(
                            self.mailbox.clone(),
                            ImapMailboxSelectOptions { parameters },
                        );
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
                            let select = ImapMailboxSelect::new(
                                self.mailbox.clone(),
                                ImapMailboxSelectOptions { parameters },
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
