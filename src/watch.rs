//! IMAP single-mailbox watcher: IDLE (RFC 2177) for the wake signal,
//! EXAMINE (QRESYNC) (RFC 7162) for UID-keyed deltas.
//!
//! The mailbox is opened with EXAMINE, not SELECT, so the session is
//! **read-only**: the watcher never writes (no flag changes, no expunge),
//! and it avoids SELECT's `\Recent` reset on every re-open.
//!
//! QRESYNC: <https://www.rfc-editor.org/rfc/rfc7162>
//!
//! ```text
//! EXAMINE (CONDSTORE) → FETCH 1:* (UID FLAGS) [seed shadow]
//!     → IDLE → EXAMINE (QRESYNC) → emit deltas → IDLE → ...
//! ```
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
//!     codec::fragmentizer::Fragmentizer,
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
//! let capability = [Capability::QResync];
//! let mailbox = "INBOX".try_into().unwrap();
//! let shutdown = Arc::new(AtomicBool::new(false));
//! let mut coroutine =
//!     ImapMailboxWatch::new(&capability, mailbox, shutdown.clone()).unwrap();
//! let mut arg = None;
//!
//! loop {
//!     match coroutine.resume(&mut fragmentizer, arg.take()) {
//!         ImapCoroutineState::Yielded(ImapMailboxWatchYield::WantsWrite(bytes)) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         ImapCoroutineState::Yielded(ImapMailboxWatchYield::WantsRead) => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
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
    /// The capability list given to `new` lacks QRESYNC.
    #[error("IMAP server does not advertise QRESYNC")]
    QresyncUnsupported,
    /// The EXAMINE response carried no UIDVALIDITY, so deltas cannot be
    /// keyed safely.
    #[error("IMAP server did not return UIDVALIDITY in EXAMINE response")]
    MissingUidValidity,
    /// The EXAMINE response carried no HIGHESTMODSEQ, so there is no
    /// resync point.
    #[error("IMAP server did not return HIGHESTMODSEQ in EXAMINE response")]
    MissingHighestModSeq,
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

/// Yield variants from the mailbox watcher.
#[derive(Debug)]
pub enum ImapMailboxWatchYield {
    /// The caller reads from its stream and resumes with the bytes.
    WantsRead,
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
    ExamineQresync(ImapMailboxExamine),
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

        // NOTE: RFC 7162 §3.1: QRESYNC implies CONDSTORE, but pass
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

    fn compute_deltas(&mut self, data: &ImapMailboxSelectData) {
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
                        debug!("enabled qresync");
                        trace!("{enabled:?}");
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
                            let Some(highest_mod_seq) = data.highest_mod_seq else {
                                return ImapCoroutineState::Complete(Err(
                                    ImapMailboxWatchError::MissingHighestModSeq,
                                ));
                            };

                            self.uid_validity = Some(uid_validity);
                            self.highest_mod_seq = highest_mod_seq;
                            debug!("examined mailbox with condstore");
                            trace!("uid_validity: {uid_validity}");
                            trace!("highest_mod_seq: {highest_mod_seq}");

                            let sequence_set: SequenceSet = match "1:*".try_into() {
                                Ok(s) => s,
                                Err(_) => {
                                    return ImapCoroutineState::Complete(Err(
                                        ImapMailboxWatchError::InvalidSequenceSet("1:*".into()),
                                    ));
                                }
                            };
                            let item_names =
                                MacroOrMessageDataItemNames::MessageDataItemNames(vec![
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
                    }
                }

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

                    self.idle_done.store(false, Ordering::SeqCst);
                    self.idle_saw_data = false;
                    let idle = ImapIdle::new(self.idle_done.clone(), ImapIdleOptions::default());
                    self.state = State::Idle(idle);
                }

                State::Idle(mut idle) => match idle.resume(fragmentizer, arg.take()) {
                    ImapCoroutineState::Yielded(ImapIdleYield::Event(_)) => {
                        debug!("idle saw untagged data");
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
                            // NOTE: uid_validity is set by ExamineInitial.
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
                            self.state = State::ExamineQresync(examine);
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
