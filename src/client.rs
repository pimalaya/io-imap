//! Blocking IMAP client wrapping a `Read + Write` stream with a
//! per-connection [`Fragmentizer`] and one method per coroutine.
//!
//! Session state is intentionally not cached: callers retain what
//! they need (capability list, selected mailbox, ...).

use core::{
    any::Any,
    fmt,
    future::Future,
    num::{NonZeroU32, NonZeroU64},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use alloc::{borrow::Cow, boxed::Box, collections::BTreeMap, string::String, vec, vec::Vec};

use std::{
    io::{self, Read, Write},
    sync::{
        Arc,
        mpsc::{self, Receiver, RecvTimeoutError, TryRecvError},
    },
    thread::{self, JoinHandle},
};

use imap_codec::{
    fragmentizer::Fragmentizer,
    imap_types::{
        command::SelectParameter,
        core::{IString, NString, Vec1},
        extensions::{
            enable::CapabilityEnable,
            sort::SortCriterion,
            thread::{Thread, ThreadingAlgorithm},
        },
        fetch::{MacroOrMessageDataItemNames, MessageDataItem},
        flag::{Flag, StoreType},
        mailbox::{ListMailbox, Mailbox},
        response::Capability,
        search::SearchKey,
        sequence::SequenceSet,
        status::{StatusDataItem, StatusDataItemName},
    },
};
#[cfg(feature = "scram")]
use io_sasl::rfc5802::SaslScramCreds;
use thiserror::Error;

#[cfg(feature = "scram")]
use crate::rfc7677::auth_scram_sha_256::*;
use crate::{
    coroutine::*,
    rfc2971::id::*,
    rfc3501::{
        append::*, append_stream::*, capability::*, check::*, close::*, copy::*, create::*,
        delete::*, examine::*, expunge::*, fetch::*, fetch_stream::*, fetch_stream_batch::*,
        greeting::*, list::*, login::*, logout::*, lsub::*, noop::*, raw::*, rename::*, search::*,
        select::*, starttls::*, status::*, store::*, subscribe::*, unsubscribe::*,
    },
    rfc3691::unselect::*,
    rfc4315::expunge_uid::*,
    rfc5161::enable::*,
    rfc5256::{sort::*, thread::*},
    rfc6851::r#move::*,
    rfc7628::auth_oauthbearer::*,
    sasl::{auth_anonymous::*, auth_login::*, auth_plain::*, auth_xoauth2::*},
    session::*,
    watch::*,
};

#[cfg(any(
    feature = "rustls-aws",
    feature = "rustls-ring",
    feature = "native-tls"
))]
mod connect;

/// Failure causes returned by [`ImapClientStd`].
#[derive(Debug, Error)]
pub enum ImapClientError {
    /// The greeting coroutine failed.
    #[error(transparent)]
    Greeting(#[from] ImapGreetingGetError),
    /// The LOGIN coroutine failed.
    #[error(transparent)]
    Login(#[from] ImapLoginError),
    /// The SASL LOGIN coroutine failed.
    #[error(transparent)]
    AuthLogin(#[from] ImapAuthLoginError),
    /// The SASL PLAIN coroutine failed.
    #[error(transparent)]
    AuthPlain(#[from] ImapAuthPlainError),
    /// The SASL ANONYMOUS coroutine failed.
    #[error(transparent)]
    AuthAnonymous(#[from] ImapAuthAnonymousError),
    /// The SASL OAUTHBEARER coroutine failed.
    #[error(transparent)]
    AuthOAuthBearer(#[from] ImapAuthOauthbearerError),
    /// The SASL XOAUTH2 coroutine failed.
    #[error(transparent)]
    AuthXOAuth2(#[from] ImapAuthXoauth2Error),
    /// The SASL SCRAM-SHA-256 coroutine failed.
    #[cfg(feature = "scram")]
    #[error(transparent)]
    AuthScramSha256(#[from] ImapAuthScramSha256Error),
    /// The session-opening coroutine failed.
    #[error(transparent)]
    SessionOpen(#[from] ImapSessionOpenError),
    /// The LOGOUT coroutine failed.
    #[error(transparent)]
    Logout(#[from] ImapLogoutError),
    /// The CAPABILITY coroutine failed.
    #[error(transparent)]
    Capability(#[from] ImapCapabilityGetError),
    /// The NOOP coroutine failed.
    #[error(transparent)]
    Noop(#[from] ImapNoopError),
    /// The raw-command coroutine failed.
    #[error(transparent)]
    Raw(#[from] ImapRawError),
    /// The ID coroutine failed.
    #[error(transparent)]
    ServerId(#[from] ImapServerIdError),
    /// The ENABLE coroutine failed.
    #[error(transparent)]
    ExtensionEnable(#[from] ImapExtensionEnableError),
    /// The LIST coroutine failed.
    #[error(transparent)]
    MailboxList(#[from] ImapMailboxListError),
    /// The LSUB coroutine failed.
    #[error(transparent)]
    MailboxLsub(#[from] ImapMailboxLsubError),
    /// The STATUS coroutine failed.
    #[error(transparent)]
    MailboxStatus(#[from] ImapMailboxStatusError),
    /// The CREATE coroutine failed.
    #[error(transparent)]
    MailboxCreate(#[from] ImapMailboxCreateError),
    /// The DELETE coroutine failed.
    #[error(transparent)]
    MailboxDelete(#[from] ImapMailboxDeleteError),
    /// The RENAME coroutine failed.
    #[error(transparent)]
    MailboxRename(#[from] ImapMailboxRenameError),
    /// The SUBSCRIBE coroutine failed.
    #[error(transparent)]
    MailboxSubscribe(#[from] ImapMailboxSubscribeError),
    /// The UNSUBSCRIBE coroutine failed.
    #[error(transparent)]
    MailboxUnsubscribe(#[from] ImapMailboxUnsubscribeError),
    /// The SELECT coroutine failed.
    #[error(transparent)]
    MailboxSelect(#[from] ImapMailboxSelectError),
    /// The EXAMINE coroutine failed.
    #[error(transparent)]
    MailboxExamine(#[from] ImapMailboxExamineError),
    /// The mailbox watcher failed.
    #[error(transparent)]
    MailboxWatch(#[from] ImapMailboxWatchError),
    /// The CLOSE coroutine failed.
    #[error(transparent)]
    MailboxClose(#[from] ImapMailboxCloseError),
    /// The UNSELECT coroutine failed.
    #[error(transparent)]
    MailboxUnselect(#[from] ImapMailboxUnselectError),
    /// The CHECK coroutine failed.
    #[error(transparent)]
    MailboxCheck(#[from] ImapMailboxCheckError),
    /// The EXPUNGE coroutine failed.
    #[error(transparent)]
    MailboxExpunge(#[from] ImapMailboxExpungeError),
    /// The UID EXPUNGE coroutine failed.
    #[error(transparent)]
    MessageExpungeUid(#[from] ImapMessageExpungeUidError),
    /// The SORT coroutine failed.
    #[error(transparent)]
    MessageSort(#[from] ImapMessageSortError),
    /// The FETCH coroutine failed.
    #[error(transparent)]
    MessageFetch(#[from] ImapMessageFetchError),
    /// The streaming FETCH coroutine failed.
    #[error(transparent)]
    MessageFetchStream(#[from] ImapMessageFetchStreamError),
    /// The batched streaming FETCH coroutine failed.
    #[error(transparent)]
    MessageFetchStreamBatch(#[from] ImapMessageFetchStreamBatchError),
    /// The SEARCH coroutine failed.
    #[error(transparent)]
    MessageSearch(#[from] ImapMessageSearchError),
    /// The STORE coroutine failed.
    #[error(transparent)]
    MessageStore(#[from] ImapMessageStoreError),
    /// The COPY coroutine failed.
    #[error(transparent)]
    MessageCopy(#[from] ImapMessageCopyError),
    /// The MOVE coroutine failed.
    #[error(transparent)]
    MessageMove(#[from] ImapMessageMoveError),
    /// The buffered APPEND coroutine failed.
    #[error(transparent)]
    MessageAppend(#[from] ImapMessageAppendError),
    /// The streaming APPEND coroutine failed.
    #[error(transparent)]
    MessageAppendStream(#[from] ImapMessageAppendStreamError),
    /// The THREAD coroutine failed.
    #[error(transparent)]
    MessageThread(#[from] ImapMessageThreadError),
    /// Reading from or writing to the stream failed.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// The STARTTLS coroutine failed.
    #[error(transparent)]
    StartTls(#[from] ImapStartTlsError),
    /// Opening the TCP/TLS connection failed.
    #[cfg(any(
        feature = "rustls-aws",
        feature = "rustls-ring",
        feature = "native-tls"
    ))]
    #[error(transparent)]
    Tls(#[from] anyhow::Error),
    /// The LOGIN user or password failed imap-types validation.
    #[error("Invalid IMAP LOGIN credentials")]
    InvalidLoginCredentials(#[from] imap_codec::imap_types::error::ValidationError),
    /// QRESYNC was requested but the capability list lacks it.
    #[error("IMAP server does not advertise QRESYNC capability")]
    QresyncNotSupported,
    /// A QRESYNC SELECT was requested with a zero mod-sequence.
    #[error("Invalid mod-sequence value: 0")]
    InvalidModSeq,
    /// The implementor's own transport failed.
    ///
    /// [`ImapClientStd`] reports I/O through [`Self::Io`]; this variant
    /// exists for implementors whose failures are something else, such
    /// as a JNI upcall or a runtime-specific socket error.
    #[error(transparent)]
    Transport(Box<dyn core::error::Error + Send + Sync>),
}

/// Emits the [`ImapClient`] and [`ImapClientAsync`] command surfaces
/// from a single list of delegations.
///
/// Both traits carry the same forty-odd one-line bodies, differing only
/// in whether they hand back a value or a future. Writing them twice is
/// how two implementations of one thing drift apart, which is the defect
/// this crate is otherwise busy removing, so the list is written once
/// and expanded twice.
macro_rules! imap_client_commands {
    (
        $(
            $(#[$meta:meta])*
            fn $name:ident($($arg:ident: $ty:ty),* $(,)?) -> $out:ty {
                $coroutine:expr
            }
        )*
    ) => {
        /// Blocking IMAP command surface: implement [`run`] and inherit
        /// every command.
        ///
        /// [`ImapClientStd`] implements it over a `Read + Write` stream;
        /// a caller whose transport is its own (a JNI upcall bridge, a
        /// pre-authenticated proxy socket, an in-memory test double)
        /// implements the same one method and gets the rest.
        ///
        /// The `Yield = ImapYield` bound on [`run`] is deliberate: it
        /// admits exactly the coroutines every client wraps identically.
        /// The five that declare their own yield vocabulary (watch,
        /// idle, streamed APPEND and the two streamed FETCHes) are the
        /// ones implementations are expected to wire differently, so
        /// they cannot be defaulted here and are not meant to be. See
        /// the examples folder for one wiring of each.
        ///
        /// The trait is not dyn-compatible, because [`run`] is generic.
        /// The dynamism this crate needs lives one layer down, at
        /// [`ImapStream`], which already spans TCP, TLS, unix sockets
        /// and foreign bridges behind a single concrete client type.
        ///
        /// [`run`]: Self::run
        pub trait ImapClient {
            /// Runs a standard-shape coroutine to completion, fulfilling
            /// its read and write requests against the transport.
            fn run<C, T, E>(&mut self, coroutine: C) -> Result<T, ImapClientError>
            where
                C: ImapCoroutine<Yield = ImapYield, Return = Result<T, E>>,
                ImapClientError: From<E>;

            $(
                $(#[$meta])*
                fn $name(&mut self, $($arg: $ty),*) -> Result<$out, ImapClientError> {
                    self.run($coroutine)
                }
            )*

            /// `LOGIN`. Channel must be TLS-protected.
            fn login(
                &mut self,
                user: &str,
                password: &str,
                opts: ImapLoginOptions,
            ) -> Result<Vec<Capability<'static>>, ImapClientError> {
                self.run(ImapLogin::new(user, password, opts)?)
            }

            /// Sends one or more caller-tagged command lines
            /// byte-for-byte and returns the verbatim server response.
            ///
            /// The bytes are written exactly as given (no tag is
            /// injected, no CRLF is trimmed or appended), so callers must
            /// tag every command and separate them with CRLF. The
            /// response spans up to and including the tagged completion
            /// of every command, which may arrive out of order.
            fn raw(&mut self, command: &[u8]) -> Result<String, ImapClientError> {
                self.run(ImapRaw::new(command)?)
            }

            /// `SELECT <mailbox> (QRESYNC ...)`.
            ///
            /// Errors with `QresyncNotSupported` when `capability` lacks
            /// QRESYNC, with `InvalidModSeq` when `highest_mod_seq` is 0.
            fn select_qresync(
                &mut self,
                mailbox: Mailbox<'static>,
                uid_validity: NonZeroU32,
                highest_mod_seq: u64,
                capability: &[Capability<'static>],
            ) -> Result<ImapMailboxSelectData, ImapClientError> {
                let parameters = qresync_parameters(uid_validity, highest_mod_seq, capability)?;
                self.select(mailbox, ImapMailboxSelectOptions { parameters })
            }
        }

        /// Async IMAP command surface, the [`ImapClient`] twin for
        /// callers whose transport is a future.
        ///
        /// Everything [`ImapClient`] documents applies here, plus the
        /// `Send` bounds. They are load-bearing rather than defensive: a
        /// plain `async fn` in a trait cannot promise that the future it
        /// returns is `Send`, so anything built from the default bodies
        /// would fail to compile under `tokio::spawn`, which is the first
        /// thing a worker-spawning consumer reaches for. Declaring the
        /// return type explicitly as `impl Future<..> + Send`, with
        /// `Send` as a supertrait so `&mut Self` carries through, keeps
        /// the defaults spawnable.
        ///
        /// [`ImapClient`] deliberately carries no such bound. A blocking
        /// call returns a value, so there is no future whose auto-traits
        /// need pinning down, and requiring `Send` there would exclude a
        /// perfectly good client built on a thread-affine handle.
        pub trait ImapClientAsync: Send {
            /// Runs a standard-shape coroutine to completion, fulfilling
            /// its read and write requests against the transport.
            fn run<C, T, E>(
                &mut self,
                coroutine: C,
            ) -> impl Future<Output = Result<T, ImapClientError>> + Send
            where
                C: ImapCoroutine<Yield = ImapYield, Return = Result<T, E>> + Send,
                T: Send,
                E: Send,
                ImapClientError: From<E>;

            $(
                $(#[$meta])*
                fn $name(
                    &mut self,
                    $($arg: $ty),*
                ) -> impl Future<Output = Result<$out, ImapClientError>> + Send {
                    self.run($coroutine)
                }
            )*

            /// `LOGIN`. Channel must be TLS-protected.
            fn login(
                &mut self,
                user: &str,
                password: &str,
                opts: ImapLoginOptions,
            ) -> impl Future<Output = Result<Vec<Capability<'static>>, ImapClientError>> + Send
            {
                async move { self.run(ImapLogin::new(user, password, opts)?).await }
            }

            /// Sends one or more caller-tagged command lines
            /// byte-for-byte and returns the verbatim server response.
            ///
            /// The bytes are written exactly as given (no tag is
            /// injected, no CRLF is trimmed or appended), so callers must
            /// tag every command and separate them with CRLF. The
            /// response spans up to and including the tagged completion
            /// of every command, which may arrive out of order.
            fn raw(
                &mut self,
                command: &[u8],
            ) -> impl Future<Output = Result<String, ImapClientError>> + Send {
                async move { self.run(ImapRaw::new(command)?).await }
            }

            /// `SELECT <mailbox> (QRESYNC ...)`.
            ///
            /// Errors with `QresyncNotSupported` when `capability` lacks
            /// QRESYNC, with `InvalidModSeq` when `highest_mod_seq` is 0.
            fn select_qresync(
                &mut self,
                mailbox: Mailbox<'static>,
                uid_validity: NonZeroU32,
                highest_mod_seq: u64,
                capability: &[Capability<'static>],
            ) -> impl Future<Output = Result<ImapMailboxSelectData, ImapClientError>> + Send
            {
                async move {
                    let parameters =
                        qresync_parameters(uid_validity, highest_mod_seq, capability)?;
                    self.select(mailbox, ImapMailboxSelectOptions { parameters })
                        .await
                }
            }
        }
    };
}

imap_client_commands! {
    /// Consumes the greeting and reports the advertised capabilities
    /// along with whether the session opened already authenticated.
    ///
    /// Forces a CAPABILITY round-trip when the greeting carried none.
    fn greeting() -> ImapGreetingOk {
        ImapGreetingGet::new(ImapGreetingGetOptions { ensure_capabilities: true })
    }

    /// `STARTTLS`. Caller still has to upgrade the socket and refresh
    /// capabilities.
    ///
    /// Returns any bytes pre-read past the tagged response; a non-empty
    /// return is a STARTTLS-injection signal, refuse the upgrade.
    /// [`ImapSessionOpen`] does that refusal for you.
    fn starttls() -> Vec<u8> {
        ImapStartTls::new()
    }

    /// SASL `AUTHENTICATE ANONYMOUS`.
    fn auth_anonymous(
        message: Option<&str>,
        opts: ImapAuthAnonymousOptions,
    ) -> Vec<Capability<'static>> {
        ImapAuthAnonymous::new(message, opts)
    }

    /// SASL `AUTHENTICATE LOGIN` (legacy). Prefer auth_plain or
    /// auth_scram_sha256 when supported.
    fn auth_login(
        user: &str,
        password: &str,
        opts: ImapAuthLoginOptions,
    ) -> Vec<Capability<'static>> {
        ImapAuthLogin::new(user, password, opts)
    }

    /// SASL `AUTHENTICATE PLAIN`.
    fn auth_plain(
        authzid: Option<&str>,
        authcid: &str,
        password: &str,
        opts: ImapAuthPlainOptions,
    ) -> Vec<Capability<'static>> {
        ImapAuthPlain::new(authzid, authcid, password, opts)
    }

    /// SASL `AUTHENTICATE OAUTHBEARER`. Channel must be TLS-protected.
    fn auth_oauthbearer(
        user: &str,
        host: &str,
        port: u16,
        token: &str,
        opts: ImapAuthOauthbearerOptions,
    ) -> Vec<Capability<'static>> {
        ImapAuthOauthbearer::new(user, host, port, token, opts)
    }

    /// SASL `AUTHENTICATE XOAUTH2` (Google's pre-standard mechanism).
    /// Prefer auth_oauthbearer when supported.
    fn auth_xoauth2(
        user: &str,
        token: &str,
        opts: ImapAuthXoauth2Options,
    ) -> Vec<Capability<'static>> {
        ImapAuthXoauth2::new(user, token, opts)
    }

    /// SASL `AUTHENTICATE SCRAM-SHA-256`.
    ///
    /// The credentials carry the client nonce, which RFC 5802 wants
    /// drawn from at least 18 bytes of cryptographic randomness, and the
    /// channel binding deciding whether the exchange announces
    /// `SCRAM-SHA-256` or `SCRAM-SHA-256-PLUS`.
    #[cfg(feature = "scram")]
    fn auth_scram_sha256(
        creds: SaslScramCreds,
        opts: ImapAuthScramSha256Options,
    ) -> Vec<Capability<'static>> {
        ImapAuthScramSha256::new(creds, opts)
    }

    /// `LOGOUT`; ends the session.
    fn logout() -> () {
        ImapLogout::new()
    }

    /// `CAPABILITY`; returns the advertised capabilities.
    fn capability() -> Vec<Capability<'static>> {
        ImapCapabilityGet::new()
    }

    /// `NOOP`; round-trips to keep the connection alive or poll for
    /// updates.
    fn noop() -> () {
        ImapNoop::new()
    }

    /// `ID`. An `opts.parameters` of `None` sends `ID NIL`.
    fn id(
        opts: ImapServerIdOptions,
    ) -> Option<Vec<(IString<'static>, NString<'static>)>> {
        ImapServerId::new(opts)
    }

    /// `ENABLE`; returns the capabilities the server confirmed enabling.
    fn enable(
        capabilities: Vec1<CapabilityEnable<'static>>,
    ) -> Option<Vec<CapabilityEnable<'static>>> {
        ImapExtensionEnable::new(capabilities)
    }

    /// `LIST`; returns the mailboxes matching `reference` and `pattern`.
    fn list(
        reference: Mailbox<'static>,
        pattern: ListMailbox<'static>,
    ) -> ImapMailboxListing {
        ImapMailboxList::new(reference, pattern)
    }

    /// `LSUB`; returns the subscribed mailboxes matching `reference` and
    /// `pattern`.
    fn lsub(
        reference: Mailbox<'static>,
        pattern: ListMailbox<'static>,
    ) -> ImapMailboxListing {
        ImapMailboxLsub::new(reference, pattern)
    }

    /// `STATUS`; returns the requested status items for `mailbox`.
    fn status(
        mailbox: Mailbox<'static>,
        item_names: Cow<'static, [StatusDataItemName]>,
    ) -> Vec<StatusDataItem> {
        ImapMailboxStatus::new(mailbox, item_names)
    }

    /// `CREATE`; creates `mailbox`.
    fn create(mailbox: Mailbox<'static>) -> () {
        ImapMailboxCreate::new(mailbox)
    }

    /// `DELETE`; deletes `mailbox`.
    fn delete(mailbox: Mailbox<'static>) -> () {
        ImapMailboxDelete::new(mailbox)
    }

    /// `RENAME`; renames mailbox `from` to `to`.
    fn rename(from: Mailbox<'static>, to: Mailbox<'static>) -> () {
        ImapMailboxRename::new(from, to)
    }

    /// `SUBSCRIBE`; subscribes to `mailbox`.
    fn subscribe(mailbox: Mailbox<'static>) -> () {
        ImapMailboxSubscribe::new(mailbox)
    }

    /// `UNSUBSCRIBE`; unsubscribes from `mailbox`.
    fn unsubscribe(mailbox: Mailbox<'static>) -> () {
        ImapMailboxUnsubscribe::new(mailbox)
    }

    /// `SELECT`; opens `mailbox` for read-write and returns its state.
    fn select(
        mailbox: Mailbox<'static>,
        opts: ImapMailboxSelectOptions,
    ) -> ImapMailboxSelectData {
        ImapMailboxSelect::new(mailbox, opts)
    }

    /// `EXAMINE`; opens `mailbox` read-only and returns its state.
    fn examine(
        mailbox: Mailbox<'static>,
        opts: ImapMailboxExamineOptions,
    ) -> ImapMailboxSelectData {
        ImapMailboxExamine::new(mailbox, opts)
    }

    /// `CLOSE`; expunges deleted messages and unselects the mailbox.
    fn close() -> () {
        ImapMailboxClose::new()
    }

    /// `UNSELECT`; unselects the mailbox without expunging.
    fn unselect() -> () {
        ImapMailboxUnselect::new()
    }

    /// `CHECK`; requests a mailbox checkpoint.
    fn check() -> () {
        ImapMailboxCheck::new()
    }

    /// `EXPUNGE`; returns the expunged sequence numbers.
    fn expunge() -> Vec<NonZeroU32> {
        ImapMailboxExpunge::new()
    }

    /// `UID EXPUNGE <sequence_set>` (RFC 4315); permanently removes only
    /// the `\Deleted` messages whose UID is in `sequence_set`, leaving
    /// any other `\Deleted` message untouched.
    ///
    /// Requires the server to advertise `UIDPLUS`; returns the expunged
    /// sequence numbers.
    fn uid_expunge(sequence_set: SequenceSet) -> Vec<NonZeroU32> {
        ImapMessageExpungeUid::new(sequence_set)
    }

    /// `FETCH`; returns the requested items keyed by message id.
    fn fetch(
        sequence_set: SequenceSet,
        items: MacroOrMessageDataItemNames<'static>,
        opts: ImapMessageFetchOptions,
    ) -> BTreeMap<NonZeroU32, Vec1<MessageDataItem<'static>>> {
        ImapMessageFetch::new(sequence_set, items, opts)
    }

    /// `SEARCH`; returns the ids matching `criteria`.
    fn search(
        criteria: Vec1<SearchKey<'static>>,
        opts: ImapMessageSearchOptions,
    ) -> Vec<NonZeroU32> {
        ImapMessageSearch::new(criteria, opts)
    }

    /// `STORE` (echo variant); returns the server-reported FETCH echoes.
    fn store(
        sequence_set: SequenceSet,
        kind: StoreType,
        flags: Vec<Flag<'static>>,
        opts: ImapMessageStoreOptions,
    ) -> BTreeMap<NonZeroU32, Vec1<MessageDataItem<'static>>> {
        ImapMessageStore::new(sequence_set, kind, flags, opts)
    }

    /// `COPY`; copies messages to `mailbox` and returns the optional
    /// COPYUID pair.
    fn copy(
        sequence_set: SequenceSet,
        mailbox: Mailbox<'static>,
        opts: ImapMessageCopyOptions,
    ) -> ImapCopyUid {
        ImapMessageCopy::new(sequence_set, mailbox, opts)
    }

    /// `MOVE`; moves messages to `mailbox` and returns the optional
    /// COPYUID pair.
    fn r#move(
        sequence_set: SequenceSet,
        mailbox: Mailbox<'static>,
        opts: ImapMessageMoveOptions,
    ) -> ImapCopyUid {
        ImapMessageMove::new(sequence_set, mailbox, opts)
    }

    /// `APPEND`; returns the optional EXISTS count and APPENDUID pair.
    ///
    /// Buffered: the whole `message` is held in memory. For large
    /// messages prefer the streaming APPEND coroutine.
    fn append(
        mailbox: Mailbox<'static>,
        message: &[u8],
        opts: ImapMessageAppendOptions,
    ) -> ImapMessageAppendOutput {
        ImapMessageAppend::new(mailbox, message.to_vec(), opts)
    }

    /// `SORT` with a client-side fallback.
    ///
    /// With `opts.fallback == false` this is a plain server SORT; with
    /// `opts.fallback == true` it SEARCHes, FETCHes the sort keys, and
    /// sorts locally. Feed `fallback` from a SORT capability check (the
    /// server SORT requires the extension).
    fn sort(
        sort_criteria: Vec1<SortCriterion>,
        search_criteria: Vec1<SearchKey<'static>>,
        opts: ImapMessageSortOptions,
    ) -> Vec<NonZeroU32> {
        ImapMessageSort::new(sort_criteria, search_criteria, opts)
    }

    /// `THREAD`; returns the message threads matching `search_criteria`.
    fn thread(
        algorithm: ThreadingAlgorithm<'static>,
        search_criteria: Vec1<SearchKey<'static>>,
        opts: ImapMessageThreadOptions,
    ) -> Vec<Thread> {
        ImapMessageThread::new(algorithm, search_criteria, opts)
    }
}

/// Validates a QRESYNC SELECT against the advertised capabilities,
/// shared by both traits' `select_qresync`.
fn qresync_parameters(
    uid_validity: NonZeroU32,
    highest_mod_seq: u64,
    capability: &[Capability<'static>],
) -> Result<Vec<SelectParameter>, ImapClientError> {
    if !capability.contains(&Capability::QResync) {
        return Err(ImapClientError::QresyncNotSupported);
    }

    let Some(mod_sequence_value) = NonZeroU64::new(highest_mod_seq) else {
        return Err(ImapClientError::InvalidModSeq);
    };

    Ok(vec![SelectParameter::QResync {
        uid_validity,
        mod_sequence_value,
        known_uids: None,
        seq_match_data: None,
    }])
}

const READ_BUFFER_SIZE: usize = 16 * 1024;
/// Buffer for streaming a message body from the socket into the caller's sink.
/// Larger than [`READ_BUFFER_SIZE`] because a body transfer is bulk data, not
/// line-oriented parsing: 128 KB cuts the `read`/`write` syscall count (and TLS
/// record crossings) on a large body versus the 8 KB `io::copy` default, for a
/// small `sys`-time win. Heap-allocated once per fetch and reused.
const BODY_COPY_BUFFER_SIZE: usize = 128 * 1024;
const FRAGMENTIZER_MAX_MESSAGE_SIZE: u32 = 100 * 1024 * 1024;

// NOTE: both are protocol constants rather than client state, so they
// live next to the scheme table in the session module and stay reachable
// without the client feature. Re-exported here because config layers
// already reach for them through this path.
pub use crate::session::{default_alpn, default_port};

/// Blocking IMAP client: a stream, the connection-wide `Fragmentizer`
/// and one method per coroutine.
pub struct ImapClientStd {
    /// The stream carrying the connection to the IMAP server.
    pub stream: Box<dyn ImapStream>,
    /// The connection-wide parser buffer shared by every coroutine run
    /// on this connection.
    pub fragmentizer: Fragmentizer,
    /// ID parameters consumed by every auth_*/login call; required by
    /// a few providers (mail.qq.com, fastmail).
    ///
    /// `None` skips, `Some(empty)` sends `ID NIL`, `Some(params)`
    /// sends `ID (k v ...)`.
    pub auto_id: Option<Vec<(IString<'static>, NString<'static>)>>,
    /// Whether the server greeting was `PREAUTH`: the session opened
    /// already authenticated (a socket proxy such as sirup), so
    /// [`connect`](Self::connect) skipped the SASL step. Stays `false`
    /// on a freshly-opened connection.
    pub pre_authenticated: bool,
}

impl ImapClient for ImapClientStd {
    fn run<C, T, E>(&mut self, mut coroutine: C) -> Result<T, ImapClientError>
    where
        C: ImapCoroutine<Yield = ImapYield, Return = Result<T, E>>,
        ImapClientError: From<E>,
    {
        let mut buf = [0u8; READ_BUFFER_SIZE];
        let mut arg: Option<&[u8]> = None;

        loop {
            match coroutine.resume(&mut self.fragmentizer, arg.take()) {
                ImapCoroutineState::Complete(Ok(out)) => return Ok(out),
                ImapCoroutineState::Complete(Err(err)) => return Err(err.into()),
                ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
                    let n = self.read_response(&mut buf)?;
                    arg = Some(&buf[..n]);
                }
                ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
                    self.stream.write_all(&bytes)?;
                    arg = None;
                }
            }
        }
    }
}

impl ImapClientStd {
    /// Caller is responsible for opening the connection (TCP, TLS,
    /// STARTTLS).
    pub fn new<S: ImapStream + 'static>(stream: S) -> Self {
        Self {
            stream: Box::new(stream),
            fragmentizer: Fragmentizer::new(FRAGMENTIZER_MAX_MESSAGE_SIZE),
            auto_id: None,
            pre_authenticated: false,
        }
    }

    /// Reads the next bytes of a server response, a closed connection
    /// being an `UnexpectedEof` failure rather than an empty read.
    ///
    /// Mid-response is the wrong place for the peer to hang up: the
    /// coroutine waiting on those bytes would otherwise be resumed with
    /// an empty slice forever. Not-ready failures never reach here, the
    /// stream retrying them under its own strategy.
    fn read_response(&mut self, buf: &mut [u8]) -> Result<usize, ImapClientError> {
        match self.stream.read(buf)? {
            0 => {
                let kind = io::ErrorKind::UnexpectedEof;
                let err = io::Error::new(kind, "IMAP server closed the connection");
                Err(err.into())
            }
            n => Ok(n),
        }
    }

    /// Useful after a STARTTLS upgrade or on reconnection.
    pub fn set_stream<S: ImapStream + 'static>(&mut self, stream: S) {
        self.stream = Box::new(stream);
    }

    /// Consumes the client into a background watcher.
    ///
    /// Drop the returned stream (or call its `close`) to wind down.
    /// `capability` selects the QRESYNC path or the whole-mailbox
    /// fallback, and `opts.shutdown_poll` how long winding down may
    /// take.
    pub fn watch_mailbox(
        self,
        mailbox: Mailbox<'static>,
        capability: &[Capability<'static>],
        opts: ImapMailboxWatchStreamOptions,
    ) -> Result<ImapMailboxWatchStream, ImapClientError> {
        let shutdown = Arc::new(AtomicBool::new(false));
        let mut watcher = ImapMailboxWatch::new(capability, mailbox, shutdown.clone());
        let mut fragmentizer = self.fragmentizer;
        let mut stream = self.stream;

        stream.set_read_timeout(Some(opts.shutdown_poll))?;
        stream.stop_retrying();

        let (tx, rx) = mpsc::sync_channel::<Result<ImapMailboxWatchEvent, ImapClientError>>(256);
        let shutdown_handle = shutdown.clone();
        let handle = thread::spawn(move || {
            let mut buf = [0u8; READ_BUFFER_SIZE];
            let mut arg: Option<Vec<u8>> = None;

            loop {
                match watcher.resume(&mut fragmentizer, arg.as_deref()) {
                    ImapCoroutineState::Yielded(ImapMailboxWatchYield::Event(e)) => {
                        arg = None;
                        if tx.send(Ok(e)).is_err() {
                            return;
                        }
                    }
                    ImapCoroutineState::Complete(Ok(())) => return,
                    ImapCoroutineState::Yielded(ImapMailboxWatchYield::WantsRead) => {
                        match stream.read(&mut buf) {
                            Ok(0) => {
                                let eof = io::ErrorKind::UnexpectedEof;
                                let err = "IMAP server closed the connection during watch";
                                tx.send(Err(io::Error::new(eof, err).into())).ok();
                                return;
                            }
                            Ok(n) => arg = Some(buf[..n].to_vec()),
                            // NOTE: the SO_RCVTIMEO wakeup this loop arms
                            // on purpose, which is why retries were turned
                            // off above: here a not-ready stream is not a
                            // failure but the periodic chance to re-check
                            // shutdown and otherwise resume, so the
                            // coroutine can observe the flag and issue
                            // IDLE DONE.
                            Err(err)
                                if matches!(
                                    err.kind(),
                                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                                ) =>
                            {
                                if shutdown.load(Ordering::SeqCst) {
                                    return;
                                }
                                arg = None;
                            }
                            Err(err) => {
                                tx.send(Err(err.into())).ok();
                                return;
                            }
                        }
                    }
                    ImapCoroutineState::Yielded(ImapMailboxWatchYield::WantsWrite(bytes)) => {
                        if let Err(err) = stream.write_all(&bytes) {
                            tx.send(Err(err.into())).ok();
                            return;
                        }
                        arg = None;
                    }
                    ImapCoroutineState::Complete(Err(err)) => {
                        tx.send(Err(err.into())).ok();
                        return;
                    }
                }
            }
        });

        Ok(ImapMailboxWatchStream {
            rx,
            handle: Some(handle),
            shutdown: shutdown_handle,
        })
    }

    /// `FETCH <id> (BODY.PEEK[])` streaming the message body straight
    /// into `sink`; the body never lands in memory whole.
    ///
    /// Peek leaves `\Seen` untouched. Returns once the tagged response
    /// is parsed; a missing id completes with an empty sink.
    pub fn fetch_body_stream(
        &mut self,
        id: NonZeroU32,
        uid: bool,
        mut sink: impl Write,
    ) -> Result<(), ImapClientError> {
        let mut coroutine = ImapMessageFetchStream::new(id, uid);
        let mut buf = [0u8; READ_BUFFER_SIZE];
        let mut body_buf = vec![0u8; BODY_COPY_BUFFER_SIZE];
        let mut arg: Option<&[u8]> = None;

        loop {
            match coroutine.resume(&mut self.fragmentizer, arg.take()) {
                ImapCoroutineState::Complete(Ok(())) => return Ok(()),
                ImapCoroutineState::Complete(Err(err)) => return Err(err.into()),
                ImapCoroutineState::Yielded(ImapMessageFetchStreamYield::WantsRead) => {
                    let n = self.read_response(&mut buf)?;
                    arg = Some(&buf[..n]);
                }
                ImapCoroutineState::Yielded(ImapMessageFetchStreamYield::WantsWrite(bytes)) => {
                    self.stream.write_all(&bytes)?;
                    arg = None;
                }
                ImapCoroutineState::Yielded(ImapMessageFetchStreamYield::BodyChunk(bytes)) => {
                    sink.write_all(&bytes)?;
                    arg = None;
                }
                ImapCoroutineState::Yielded(ImapMessageFetchStreamYield::WantsStream { len }) => {
                    let mut remaining = len as u64;
                    let mut short = false;

                    while remaining > 0 {
                        let want = remaining.min(body_buf.len() as u64) as usize;
                        let n = self.stream.read(&mut body_buf[..want])?;
                        if n == 0 {
                            short = true;
                            break;
                        }
                        sink.write_all(&body_buf[..n])?;
                        remaining -= n as u64;
                    }

                    arg = short.then_some(&[]);
                }
            }
        }
    }

    /// `UID FETCH <set> (UID BODY.PEEK[])` streaming every message body in one
    /// command — N bodies for one round trip. Each message is routed to its own
    /// sink: `open(uid)` returns a fresh sink when a message begins, its body is
    /// streamed into it, and `done(uid, sink)` commits it when the message ends.
    /// No body is held in memory whole. A requested UID absent on the server
    /// simply never calls `open`/`done`.
    pub fn fetch_bodies_stream<S: Write>(
        &mut self,
        sequence_set: SequenceSet,
        uid: bool,
        mut open: impl FnMut(u32) -> io::Result<S>,
        mut done: impl FnMut(u32, S) -> io::Result<()>,
    ) -> Result<(), ImapClientError> {
        let mut coroutine = ImapMessageFetchStreamBatch::new(sequence_set, uid);
        let mut buf = [0u8; READ_BUFFER_SIZE];
        let mut body_buf = vec![0u8; BODY_COPY_BUFFER_SIZE];
        // The sink of the message currently streaming, opened at MessageStart and
        // committed at MessageEnd.
        let mut current: Option<(u32, S)> = None;
        let mut arg: Option<&[u8]> = None;

        loop {
            match coroutine.resume(&mut self.fragmentizer, arg.take()) {
                ImapCoroutineState::Complete(Ok(())) => return Ok(()),
                ImapCoroutineState::Complete(Err(err)) => return Err(err.into()),
                ImapCoroutineState::Yielded(ImapMessageFetchStreamBatchYield::WantsRead) => {
                    let n = self.read_response(&mut buf)?;
                    arg = Some(&buf[..n]);
                }
                ImapCoroutineState::Yielded(ImapMessageFetchStreamBatchYield::WantsWrite(
                    bytes,
                )) => {
                    self.stream.write_all(&bytes)?;
                    arg = None;
                }
                ImapCoroutineState::Yielded(ImapMessageFetchStreamBatchYield::MessageStart {
                    uid,
                }) => {
                    current = Some((uid, open(uid)?));
                    arg = None;
                }
                ImapCoroutineState::Yielded(ImapMessageFetchStreamBatchYield::BodyChunk(bytes)) => {
                    let (_, sink) = current.as_mut().expect("body chunk within a message");
                    sink.write_all(&bytes)?;
                    arg = None;
                }
                ImapCoroutineState::Yielded(ImapMessageFetchStreamBatchYield::WantsStream {
                    len,
                }) => {
                    let (_, sink) = current.as_mut().expect("stream within a message");
                    let mut remaining = len as u64;
                    let mut short = false;
                    while remaining > 0 {
                        let want = remaining.min(body_buf.len() as u64) as usize;
                        let n = self.stream.read(&mut body_buf[..want])?;
                        if n == 0 {
                            short = true;
                            break;
                        }
                        sink.write_all(&body_buf[..n])?;
                        remaining -= n as u64;
                    }
                    arg = short.then_some(&[]);
                }
                ImapCoroutineState::Yielded(ImapMessageFetchStreamBatchYield::MessageEnd) => {
                    let (uid, sink) = current.take().expect("message end within a message");
                    done(uid, sink)?;
                    arg = None;
                }
            }
        }
    }

    /// `APPEND` streaming `len` octets from `source` straight to the
    /// socket; the body never lands in memory whole.
    ///
    /// `len` must match the source exactly: IMAP declares the octet
    /// count up front, so a shorter source poisons the connection.
    /// Synchronising by default so the server can reject before the
    /// body is sent; set `opts.non_sync` to skip the wait.
    pub fn append_stream(
        &mut self,
        mailbox: Mailbox<'static>,
        mut source: impl Read,
        len: usize,
        opts: ImapMessageAppendOptions,
    ) -> Result<ImapMessageAppendOutput, ImapClientError> {
        let mut coroutine = ImapMessageAppendStream::new(mailbox, len as u32, opts);
        let mut buf = [0u8; READ_BUFFER_SIZE];
        let mut arg: Option<&[u8]> = None;

        loop {
            match coroutine.resume(&mut self.fragmentizer, arg.take()) {
                ImapCoroutineState::Complete(Ok(out)) => return Ok(out),
                ImapCoroutineState::Complete(Err(err)) => return Err(err.into()),
                ImapCoroutineState::Yielded(ImapMessageAppendStreamYield::WantsRead) => {
                    let n = self.read_response(&mut buf)?;
                    arg = Some(&buf[..n]);
                }
                ImapCoroutineState::Yielded(ImapMessageAppendStreamYield::WantsWrite(bytes)) => {
                    self.stream.write_all(&bytes)?;
                    arg = None;
                }
                ImapCoroutineState::Yielded(ImapMessageAppendStreamYield::WantsStream) => {
                    let len = len as u64;
                    let mut sink = source.by_ref().take(len);
                    let n = io::copy(&mut sink, &mut self.stream)?;
                    arg = (n != len).then_some(&[]);
                }
            }
        }
    }
}

impl fmt::Debug for ImapClientStd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImapClientStd")
            .field("fragmentizer", &self.fragmentizer)
            .finish_non_exhaustive()
    }
}

/// Options of [`ImapClientStd::watch_mailbox`].
#[derive(Clone, Copy, Debug)]
pub struct ImapMailboxWatchStreamOptions {
    /// How long the worker may sit in a read before it looks at the
    /// shutdown flag again.
    ///
    /// It is the read deadline armed on the stream, so it is also the
    /// worst case for [`ImapMailboxWatchStream::close`] against a
    /// silent server: the worker is blocked in a read until then. A
    /// caller that wants a prompt Ctrl+C picks a second or less and
    /// pays a wakeup per interval; the default of five seconds suits a
    /// long-running watch nobody is waiting on.
    pub shutdown_poll: Duration,
}

impl Default for ImapMailboxWatchStreamOptions {
    fn default() -> Self {
        Self {
            shutdown_poll: Duration::from_secs(5),
        }
    }
}

/// Background-worker watch stream; drop or [`Self::close`] to wind down.
pub struct ImapMailboxWatchStream {
    rx: Receiver<Result<ImapMailboxWatchEvent, ImapClientError>>,
    handle: Option<JoinHandle<()>>,
    shutdown: Arc<AtomicBool>,
}

impl ImapMailboxWatchStream {
    /// Non-blocking probe for the next event.
    pub fn try_recv(&self) -> Result<Result<ImapMailboxWatchEvent, ImapClientError>, TryRecvError> {
        self.rx.try_recv()
    }

    /// Waits up to `timeout` for the next event.
    pub fn recv_timeout(
        &self,
        timeout: Duration,
    ) -> Result<Result<ImapMailboxWatchEvent, ImapClientError>, RecvTimeoutError> {
        self.rx.recv_timeout(timeout)
    }

    /// Signals shutdown and joins the worker.
    pub fn close(mut self) -> Result<(), ImapClientError> {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            handle
                .join()
                .map_err(|_| io::Error::other("IMAP watch worker panicked"))?;
        }
        Ok(())
    }
}

impl Iterator for ImapMailboxWatchStream {
    type Item = Result<ImapMailboxWatchEvent, ImapClientError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.rx.recv().ok()
    }
}

impl Drop for ImapMailboxWatchStream {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);

        if let Some(handle) = self.handle.take() {
            handle.join().ok();
        }
    }
}

/// Blocking stream the client runs over.
///
/// Implemented for the standard pimalaya-stream transport; a custom one (such
/// as a JNI upcall bridge) implements it directly. `as_any_mut`
/// supports downcasting back to the concrete stream when a caller needs
/// a type-specific handle (e.g. sirup's socket proxy).
pub trait ImapStream: Read + Write + Send + Any {
    /// The stream as a mutable `Any`, ready for downcasting.
    fn as_any_mut(&mut self) -> &mut dyn Any;

    /// Bounds each blocking read, used by the mailbox watch worker for a
    /// periodic shutdown-poll wakeup. A transport that cannot honor it
    /// returns `Ok(())` and manages its own read semantics.
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;

    /// Hands the failures that only mean "not ready yet" back to the
    /// caller instead of retrying them, for good.
    ///
    /// The mailbox watch worker is what needs it: it arms a read
    /// timeout precisely to be woken up, and a stream retrying the
    /// wakeup away would leave the shutdown flag unchecked until the
    /// server speaks. A transport that never retries has nothing to
    /// turn off.
    fn stop_retrying(&mut self) {}
}
