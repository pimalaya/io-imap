//! Blocking IMAP client wrapping a `Read + Write` stream with a
//! per-connection [`Fragmentizer`] and one method per coroutine.
//!
//! Session state is intentionally not cached: callers retain what
//! they need (capability list, selected mailbox, ...).

use core::{
    any::Any,
    fmt,
    num::{NonZeroU32, NonZeroU64},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

#[cfg(any(
    feature = "rustls-aws",
    feature = "rustls-ring",
    feature = "native-tls"
))]
use alloc::string::ToString;
use alloc::{borrow::Cow, boxed::Box, collections::BTreeMap, string::String, vec::Vec};
#[cfg(any(
    feature = "rustls-aws",
    feature = "rustls-ring",
    feature = "native-tls"
))]
use secrecy::ExposeSecret;

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
#[cfg(any(
    feature = "rustls-aws",
    feature = "rustls-ring",
    feature = "native-tls"
))]
use pimalaya_stream::sasl::SaslScramSha256;
#[cfg(any(
    feature = "rustls-aws",
    feature = "rustls-ring",
    feature = "native-tls"
))]
use pimalaya_stream::{
    sasl::{Sasl, SaslAnonymous, SaslLogin, SaslOauthbearer, SaslPlain, SaslXoauth2},
    std::stream::StreamStd,
    tls::Tls,
};
use thiserror::Error;
#[cfg(any(
    feature = "rustls-aws",
    feature = "rustls-ring",
    feature = "native-tls"
))]
use url::Url;

#[cfg(feature = "scram")]
use crate::rfc7677::auth_scram_sha_256::*;
use crate::{
    coroutine::*,
    rfc2971::id::*,
    rfc3501::{
        append::*, append_stream::*, capability::*, check::*, close::*, copy::*, create::*,
        delete::*, examine::*, expunge::*, fetch::*, fetch_stream::*, greeting::*, list::*,
        login::*, logout::*, lsub::*, noop::*, rename::*, search::*, select::*, starttls::*,
        status::*, store::*, subscribe::*, unsubscribe::*,
    },
    rfc3691::unselect::*,
    rfc5161::enable::*,
    rfc5256::{sort::*, thread::*},
    rfc6851::r#move::*,
    rfc7628::auth_oauthbearer::*,
    sasl::{auth_anonymous::*, auth_login::*, auth_plain::*, auth_xoauth2::*},
    watch::*,
};

/// Failure causes returned by [`ImapClientStd`].
#[derive(Debug, Error)]
pub enum ImapClientStdError {
    #[error(transparent)]
    Greeting(#[from] ImapGreetingGetError),
    #[error(transparent)]
    Login(#[from] ImapLoginError),
    #[error(transparent)]
    AuthLogin(#[from] ImapAuthLoginError),
    #[error(transparent)]
    AuthPlain(#[from] ImapAuthPlainError),
    #[error(transparent)]
    AuthAnonymous(#[from] ImapAuthAnonymousError),
    #[error(transparent)]
    AuthOAuthBearer(#[from] ImapAuthOauthbearerError),
    #[error(transparent)]
    AuthXOAuth2(#[from] ImapAuthXoauth2Error),
    #[cfg(feature = "scram")]
    #[error(transparent)]
    AuthScramSha256(#[from] ImapAuthScramSha256Error),
    #[cfg(any(
        feature = "rustls-aws",
        feature = "rustls-ring",
        feature = "native-tls"
    ))]
    #[cfg(not(feature = "scram"))]
    #[error("SCRAM-SHA-256 SASL mechanism requires the `scram` cargo feature")]
    ScramSha256NotEnabled,
    #[error(transparent)]
    Logout(#[from] ImapLogoutError),

    #[error(transparent)]
    Capability(#[from] ImapCapabilityGetError),
    #[error(transparent)]
    Noop(#[from] ImapNoopError),
    #[error(transparent)]
    ServerId(#[from] ImapServerIdError),
    #[error(transparent)]
    ExtensionEnable(#[from] ImapExtensionEnableError),

    #[error(transparent)]
    MailboxList(#[from] ImapMailboxListError),
    #[error(transparent)]
    MailboxLsub(#[from] ImapMailboxLsubError),
    #[error(transparent)]
    MailboxStatus(#[from] ImapMailboxStatusError),
    #[error(transparent)]
    MailboxCreate(#[from] ImapMailboxCreateError),
    #[error(transparent)]
    MailboxDelete(#[from] ImapMailboxDeleteError),
    #[error(transparent)]
    MailboxRename(#[from] ImapMailboxRenameError),
    #[error(transparent)]
    MailboxSubscribe(#[from] ImapMailboxSubscribeError),
    #[error(transparent)]
    MailboxUnsubscribe(#[from] ImapMailboxUnsubscribeError),
    #[error(transparent)]
    MailboxSelect(#[from] ImapMailboxSelectError),
    #[error(transparent)]
    MailboxExamine(#[from] ImapMailboxExamineError),
    #[error(transparent)]
    MailboxWatch(#[from] ImapMailboxWatchError),
    #[error(transparent)]
    MailboxClose(#[from] ImapMailboxCloseError),
    #[error(transparent)]
    MailboxUnselect(#[from] ImapMailboxUnselectError),
    #[error(transparent)]
    MailboxCheck(#[from] ImapMailboxCheckError),
    #[error(transparent)]
    MailboxExpunge(#[from] ImapMailboxExpungeError),
    #[error(transparent)]
    MessageSort(#[from] ImapMessageSortError),

    #[error(transparent)]
    MessageFetch(#[from] ImapMessageFetchError),
    #[error(transparent)]
    MessageFetchStream(#[from] ImapMessageFetchStreamError),
    #[error(transparent)]
    MessageSearch(#[from] ImapMessageSearchError),
    #[error(transparent)]
    MessageStore(#[from] ImapMessageStoreError),
    #[error(transparent)]
    MessageCopy(#[from] ImapMessageCopyError),
    #[error(transparent)]
    MessageMove(#[from] ImapMessageMoveError),
    #[error(transparent)]
    MessageAppend(#[from] ImapMessageAppendError),
    #[error(transparent)]
    MessageAppendStream(#[from] ImapMessageAppendStreamError),
    #[error(transparent)]
    MessageThread(#[from] ImapMessageThreadError),

    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    StartTls(#[from] ImapStartTlsError),
    #[cfg(any(
        feature = "rustls-aws",
        feature = "rustls-ring",
        feature = "native-tls"
    ))]
    #[error(transparent)]
    Tls(#[from] anyhow::Error),
    #[cfg(any(
        feature = "rustls-aws",
        feature = "rustls-ring",
        feature = "native-tls"
    ))]
    #[error("IMAP URL `{0}` has no host")]
    UrlMissingHost(String),
    #[cfg(any(
        feature = "rustls-aws",
        feature = "rustls-ring",
        feature = "native-tls"
    ))]
    #[error("IMAP URL `{0}` has unsupported scheme `{1}` (expected `imap` or `imaps`)")]
    UrlUnsupportedScheme(String, String),
    #[cfg(any(
        feature = "rustls-aws",
        feature = "rustls-ring",
        feature = "native-tls"
    ))]
    #[error("STARTTLS requested on an `imaps://` URL: TLS is already active")]
    StartTlsOverTls,
    #[error("Invalid IMAP LOGIN credentials")]
    InvalidLoginCredentials(#[from] imap_codec::imap_types::error::ValidationError),

    #[error("IMAP server does not advertise QRESYNC capability")]
    QresyncNotSupported,
    #[error("Invalid mod-sequence value: 0")]
    InvalidModSeq,
}

const READ_BUFFER_SIZE: usize = 16 * 1024;
const FRAGMENTIZER_MAX_MESSAGE_SIZE: u32 = 100 * 1024 * 1024;

/// Default ALPN identifier for IMAP TLS (RFC 7595).
pub fn default_alpn() -> Vec<String> {
    vec![String::from("imap")]
}

/// `auto_id` is consumed by every auth_*/login: `None` skips,
/// `Some(empty)` sends `ID NIL`, `Some(params)` sends `ID (k v ...)`.
/// Required by a few providers (mail.qq.com, fastmail).
pub struct ImapClientStd {
    pub stream: Box<dyn ImapStream>,
    pub fragmentizer: Fragmentizer,
    pub auto_id: Option<Vec<(IString<'static>, NString<'static>)>>,
}

impl ImapClientStd {
    /// Caller is responsible for opening the connection (TCP, TLS,
    /// STARTTLS).
    pub fn new<S: Read + Write + Send + 'static>(stream: S) -> Self {
        Self {
            stream: Box::new(stream),
            fragmentizer: Fragmentizer::new(FRAGMENTIZER_MAX_MESSAGE_SIZE),
            auto_id: None,
        }
    }

    /// Useful after a STARTTLS upgrade or on reconnection.
    pub fn set_stream<S: Read + Write + Send + 'static>(&mut self, stream: S) {
        self.stream = Box::new(stream);
    }

    /// Drives a standard-shape coroutine to completion. Richer yields (IDLE
    /// events, watch deltas) need their own per-method loops.
    pub fn run<C, T, E>(&mut self, mut coroutine: C) -> Result<T, ImapClientStdError>
    where
        C: ImapCoroutine<Yield = ImapYield, Return = Result<T, E>>,
        ImapClientStdError: From<E>,
    {
        let mut buf = [0u8; READ_BUFFER_SIZE];
        let mut arg: Option<&[u8]> = None;

        loop {
            match coroutine.resume(&mut self.fragmentizer, arg.take()) {
                ImapCoroutineState::Complete(Ok(out)) => return Ok(out),
                ImapCoroutineState::Complete(Err(err)) => return Err(err.into()),
                ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
                    let n = self.stream.read(&mut buf)?;
                    arg = Some(&buf[..n]);
                }
                ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
                    self.stream.write_all(&bytes)?;
                    arg = None;
                }
            }
        }
    }

    // ---- Session lifecycle ------------------------------------------------

    /// Consumes the greeting and returns the advertised capabilities
    /// (forcing a CAPABILITY round-trip if the greeting carried none).
    pub fn greeting(&mut self) -> Result<Vec<Capability<'static>>, ImapClientStdError> {
        Ok(self
            .run(ImapGreetingGet::new(ImapGreetingGetOptions {
                ensure_capabilities: true,
            }))?
            .capability)
    }

    /// `LOGIN`. Channel must be TLS-protected. Consumes `auto_id`.
    pub fn login(
        &mut self,
        user: impl AsRef<str>,
        password: impl AsRef<str>,
        opts: ImapLoginOptions,
    ) -> Result<Vec<Capability<'static>>, ImapClientStdError> {
        self.run(ImapLogin::new(user, password, opts)?)
    }

    /// `STARTTLS`. Caller still has to upgrade the socket and refresh
    /// capabilities. Returns any bytes pre-read past the tagged
    /// response (a non-empty return is a STARTTLS-injection signal:
    /// refuse the upgrade).
    pub fn starttls(&mut self) -> Result<Vec<u8>, ImapClientStdError> {
        self.run(ImapStartTls::new())
    }

    /// SASL `AUTHENTICATE ANONYMOUS`. Consumes `auto_id`.
    pub fn auth_anonymous(
        &mut self,
        message: Option<impl AsRef<str>>,
        opts: ImapAuthAnonymousOptions,
    ) -> Result<Vec<Capability<'static>>, ImapClientStdError> {
        self.run(ImapAuthAnonymous::new(message, opts))
    }

    /// SASL `AUTHENTICATE LOGIN` (legacy). Prefer auth_plain or
    /// auth_scram_sha256 when supported. Consumes `auto_id`.
    pub fn auth_login(
        &mut self,
        user: impl AsRef<str>,
        password: impl AsRef<str>,
        opts: ImapAuthLoginOptions,
    ) -> Result<Vec<Capability<'static>>, ImapClientStdError> {
        self.run(ImapAuthLogin::new(user, password, opts))
    }

    /// SASL `AUTHENTICATE PLAIN`. Consumes `auto_id`.
    pub fn auth_plain(
        &mut self,
        authzid: Option<impl AsRef<str>>,
        authcid: impl AsRef<str>,
        password: impl AsRef<str>,
        opts: ImapAuthPlainOptions,
    ) -> Result<Vec<Capability<'static>>, ImapClientStdError> {
        self.run(ImapAuthPlain::new(authzid, authcid, password, opts))
    }

    /// SASL `AUTHENTICATE OAUTHBEARER`. Channel must be
    /// TLS-protected. Consumes `auto_id`.
    pub fn auth_oauthbearer(
        &mut self,
        user: impl AsRef<str>,
        host: impl AsRef<str>,
        port: u16,
        token: impl AsRef<str>,
        opts: ImapAuthOauthbearerOptions,
    ) -> Result<Vec<Capability<'static>>, ImapClientStdError> {
        self.run(ImapAuthOauthbearer::new(user, host, port, token, opts))
    }

    /// SASL `AUTHENTICATE XOAUTH2` (Google's pre-standard mechanism).
    /// Prefer auth_oauthbearer when supported. Consumes `auto_id`.
    pub fn auth_xoauth2(
        &mut self,
        user: impl AsRef<str>,
        token: impl AsRef<str>,
        opts: ImapAuthXoauth2Options,
    ) -> Result<Vec<Capability<'static>>, ImapClientStdError> {
        self.run(ImapAuthXoauth2::new(user, token, opts))
    }

    /// SASL `AUTHENTICATE SCRAM-SHA-256`. Consumes `auto_id`.
    #[cfg(feature = "scram")]
    pub fn auth_scram_sha256(
        &mut self,
        user: impl AsRef<str>,
        password: impl AsRef<str>,
        opts: ImapAuthScramSha256Options,
    ) -> Result<Vec<Capability<'static>>, ImapClientStdError> {
        self.run(ImapAuthScramSha256::new(user, password, opts))
    }

    /// `LOGOUT`; ends the session.
    pub fn logout(&mut self) -> Result<(), ImapClientStdError> {
        self.run(ImapLogout::new())
    }

    // ---- State / introspection -------------------------------------------

    /// `CAPABILITY`; returns the advertised capabilities.
    pub fn capability(&mut self) -> Result<Vec<Capability<'static>>, ImapClientStdError> {
        self.run(ImapCapabilityGet::new())
    }

    /// `NOOP`; round-trips to keep the connection alive or poll for updates.
    pub fn noop(&mut self) -> Result<(), ImapClientStdError> {
        self.run(ImapNoop::new())
    }

    /// `ID`. An `opts.parameters` of `None` sends `ID NIL`.
    pub fn id(
        &mut self,
        opts: ImapServerIdOptions,
    ) -> Result<Option<Vec<(IString<'static>, NString<'static>)>>, ImapClientStdError> {
        self.run(ImapServerId::new(opts))
    }

    /// `ENABLE`; returns the capabilities the server confirmed enabling.
    pub fn enable(
        &mut self,
        capabilities: Vec1<CapabilityEnable<'static>>,
    ) -> Result<Option<Vec<CapabilityEnable<'static>>>, ImapClientStdError> {
        self.run(ImapExtensionEnable::new(capabilities))
    }

    // ---- Mailbox structure -----------------------------------------------

    /// `LIST`; returns the mailboxes matching `reference` and `pattern`.
    pub fn list(
        &mut self,
        reference: Mailbox<'static>,
        pattern: ListMailbox<'static>,
    ) -> Result<ImapMailboxListing, ImapClientStdError> {
        self.run(ImapMailboxList::new(reference, pattern))
    }

    /// `LSUB`; returns the subscribed mailboxes matching `reference` and
    /// `pattern`.
    pub fn lsub(
        &mut self,
        reference: Mailbox<'static>,
        pattern: ListMailbox<'static>,
    ) -> Result<ImapMailboxListing, ImapClientStdError> {
        self.run(ImapMailboxLsub::new(reference, pattern))
    }

    /// `STATUS`; returns the requested status items for `mailbox`.
    pub fn status(
        &mut self,
        mailbox: Mailbox<'static>,
        item_names: impl Into<Cow<'static, [StatusDataItemName]>>,
    ) -> Result<Vec<StatusDataItem>, ImapClientStdError> {
        self.run(ImapMailboxStatus::new(mailbox, item_names))
    }

    /// `CREATE`; creates `mailbox`.
    pub fn create(&mut self, mailbox: Mailbox<'static>) -> Result<(), ImapClientStdError> {
        self.run(ImapMailboxCreate::new(mailbox))
    }

    /// `DELETE`; deletes `mailbox`.
    pub fn delete(&mut self, mailbox: Mailbox<'static>) -> Result<(), ImapClientStdError> {
        self.run(ImapMailboxDelete::new(mailbox))
    }

    /// `RENAME`; renames mailbox `from` to `to`.
    pub fn rename(
        &mut self,
        from: Mailbox<'static>,
        to: Mailbox<'static>,
    ) -> Result<(), ImapClientStdError> {
        self.run(ImapMailboxRename::new(from, to))
    }

    /// `SUBSCRIBE`; subscribes to `mailbox`.
    pub fn subscribe(&mut self, mailbox: Mailbox<'static>) -> Result<(), ImapClientStdError> {
        self.run(ImapMailboxSubscribe::new(mailbox))
    }

    /// `UNSUBSCRIBE`; unsubscribes from `mailbox`.
    pub fn unsubscribe(&mut self, mailbox: Mailbox<'static>) -> Result<(), ImapClientStdError> {
        self.run(ImapMailboxUnsubscribe::new(mailbox))
    }

    // ---- Mailbox selection -----------------------------------------------

    /// `SELECT`; opens `mailbox` for read-write and returns its state.
    pub fn select(
        &mut self,
        mailbox: Mailbox<'static>,
        opts: ImapMailboxSelectOptions,
    ) -> Result<SelectData, ImapClientStdError> {
        self.run(ImapMailboxSelect::new(mailbox, opts))
    }

    /// `EXAMINE`; opens `mailbox` read-only and returns its state.
    pub fn examine(
        &mut self,
        mailbox: Mailbox<'static>,
        opts: ImapMailboxExamineOptions,
    ) -> Result<SelectData, ImapClientStdError> {
        self.run(ImapMailboxExamine::new(mailbox, opts))
    }

    /// `SELECT <mailbox> (QRESYNC ...)`. Errors with
    /// `QresyncNotSupported` when `capability` lacks QRESYNC, with
    /// `InvalidModSeq` when `highest_mod_seq` is 0.
    pub fn select_qresync(
        &mut self,
        mailbox: Mailbox<'static>,
        uid_validity: NonZeroU32,
        highest_mod_seq: u64,
        capability: &[Capability<'static>],
    ) -> Result<SelectData, ImapClientStdError> {
        if !capability.contains(&Capability::QResync) {
            return Err(ImapClientStdError::QresyncNotSupported);
        }

        let Some(highest_mod_seq) = NonZeroU64::new(highest_mod_seq) else {
            return Err(ImapClientStdError::InvalidModSeq);
        };

        let parameters = vec![SelectParameter::QResync {
            uid_validity,
            mod_sequence_value: highest_mod_seq,
            known_uids: None,
            seq_match_data: None,
        }];

        self.select(mailbox, ImapMailboxSelectOptions { parameters })
    }

    /// `CLOSE`; expunges deleted messages and unselects the mailbox.
    pub fn close(&mut self) -> Result<(), ImapClientStdError> {
        self.run(ImapMailboxClose::new())
    }

    /// `UNSELECT`; unselects the mailbox without expunging.
    pub fn unselect(&mut self) -> Result<(), ImapClientStdError> {
        self.run(ImapMailboxUnselect::new())
    }

    /// `CHECK`; requests a mailbox checkpoint.
    pub fn check(&mut self) -> Result<(), ImapClientStdError> {
        self.run(ImapMailboxCheck::new())
    }

    /// `EXPUNGE`; returns the expunged sequence numbers.
    pub fn expunge(&mut self) -> Result<Vec<NonZeroU32>, ImapClientStdError> {
        self.run(ImapMailboxExpunge::new())
    }

    /// Consumes the client into a background watcher. Drop the
    /// returned stream (or call its `close`) to wind down. Errors when
    /// `capability` lacks QRESYNC.
    pub fn watch_mailbox(
        self,
        mailbox: Mailbox<'static>,
        capability: &[Capability<'static>],
    ) -> Result<ImapMailboxWatchStream, ImapClientStdError> {
        let shutdown = Arc::new(AtomicBool::new(false));
        let mut watcher = ImapMailboxWatch::new(capability, mailbox, shutdown.clone())?;
        let mut fragmentizer = self.fragmentizer;
        let mut stream = self.stream;

        let (tx, rx) = mpsc::sync_channel::<Result<ImapMailboxWatchEvent, ImapClientStdError>>(256);
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

    // ---- Messages --------------------------------------------------------

    /// `FETCH`; returns the requested items keyed by message id.
    pub fn fetch(
        &mut self,
        sequence_set: SequenceSet,
        items: MacroOrMessageDataItemNames<'static>,
        opts: ImapMessageFetchOptions,
    ) -> Result<BTreeMap<NonZeroU32, Vec1<MessageDataItem<'static>>>, ImapClientStdError> {
        self.run(ImapMessageFetch::new(sequence_set, items, opts))
    }

    /// `FETCH <id> (BODY.PEEK[])` streaming the message body straight into
    /// `sink`; the body never lands in memory whole. Peek leaves `\Seen`
    /// untouched. Returns once the tagged response is parsed; a missing id
    /// completes with an empty sink.
    pub fn fetch_body_stream(
        &mut self,
        id: NonZeroU32,
        uid: bool,
        mut sink: impl Write,
    ) -> Result<(), ImapClientStdError> {
        let mut coroutine = ImapMessageFetchStream::new(id, uid);
        let mut buf = [0u8; READ_BUFFER_SIZE];
        let mut arg: Option<&[u8]> = None;

        loop {
            match coroutine.resume(&mut self.fragmentizer, arg.take()) {
                ImapCoroutineState::Complete(Ok(())) => return Ok(()),
                ImapCoroutineState::Complete(Err(err)) => return Err(err.into()),
                ImapCoroutineState::Yielded(ImapMessageFetchStreamYield::WantsRead) => {
                    let n = self.stream.read(&mut buf)?;
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
                    let len = len as u64;
                    let mut stream = (&mut self.stream).take(len);
                    let n = io::copy(&mut stream, &mut sink)?;
                    // An empty slice tells the coroutine the socket ran short
                    // of the declared body length.
                    arg = (n != len).then_some(&[]);
                }
            }
        }
    }

    /// `SEARCH`; returns the ids matching `criteria`.
    pub fn search(
        &mut self,
        criteria: Vec1<SearchKey<'static>>,
        opts: ImapMessageSearchOptions,
    ) -> Result<Vec<NonZeroU32>, ImapClientStdError> {
        self.run(ImapMessageSearch::new(criteria, opts))
    }

    /// `STORE` (echo variant); returns the server-reported FETCH echoes.
    pub fn store(
        &mut self,
        sequence_set: SequenceSet,
        kind: StoreType,
        flags: Vec<Flag<'static>>,
        opts: ImapMessageStoreOptions,
    ) -> Result<BTreeMap<NonZeroU32, Vec1<MessageDataItem<'static>>>, ImapClientStdError> {
        self.run(ImapMessageStore::new(sequence_set, kind, flags, opts))
    }

    /// `COPY`; copies messages to `mailbox` and returns the optional COPYUID
    /// pair.
    pub fn copy(
        &mut self,
        sequence_set: SequenceSet,
        mailbox: Mailbox<'static>,
        opts: ImapMessageCopyOptions,
    ) -> Result<ImapCopyUid, ImapClientStdError> {
        self.run(ImapMessageCopy::new(sequence_set, mailbox, opts))
    }

    /// `MOVE`; moves messages to `mailbox` and returns the optional COPYUID
    /// pair.
    pub fn r#move(
        &mut self,
        sequence_set: SequenceSet,
        mailbox: Mailbox<'static>,
        opts: ImapMessageMoveOptions,
    ) -> Result<ImapCopyUid, ImapClientStdError> {
        self.run(ImapMessageMove::new(sequence_set, mailbox, opts))
    }

    /// `APPEND`; returns the optional EXISTS count and APPENDUID pair.
    /// Buffered: the whole `message` is held in memory. For large messages
    /// prefer [`Self::append_stream`].
    pub fn append(
        &mut self,
        mailbox: Mailbox<'static>,
        message: &[u8],
        opts: ImapMessageAppendOptions,
    ) -> Result<ImapMessageAppendOutput, ImapClientStdError> {
        self.run(ImapMessageAppend::new(mailbox, message.to_vec(), opts))
    }

    /// `APPEND` streaming `len` octets from `source` straight to the socket;
    /// the body never lands in memory whole. `len` must match the source
    /// exactly: IMAP declares the octet count up front, so a shorter source
    /// poisons the connection. Synchronising by default so the server can
    /// reject before the body is sent; set `opts.non_sync` to skip the wait.
    pub fn append_stream(
        &mut self,
        mailbox: Mailbox<'static>,
        mut source: impl Read,
        len: usize,
        opts: ImapMessageAppendOptions,
    ) -> Result<ImapMessageAppendOutput, ImapClientStdError> {
        let mut coroutine = ImapMessageAppendStream::new(mailbox, len as u32, opts);
        let mut buf = [0u8; READ_BUFFER_SIZE];
        let mut arg: Option<&[u8]> = None;

        loop {
            match coroutine.resume(&mut self.fragmentizer, arg.take()) {
                ImapCoroutineState::Complete(Ok(out)) => return Ok(out),
                ImapCoroutineState::Complete(Err(err)) => return Err(err.into()),
                ImapCoroutineState::Yielded(ImapMessageAppendStreamYield::WantsRead) => {
                    let n = self.stream.read(&mut buf)?;
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
                    // An empty slice tells the coroutine the source ran short
                    // of the declared count.
                    arg = (n != len).then_some(&[]);
                }
            }
        }
    }

    // ---- RFC 5256: SORT / THREAD ------------------------------------------

    /// `SORT` with a client-side fallback. With `opts.fallback == false` this
    /// is a plain server SORT; with `opts.fallback == true` it SEARCHes,
    /// FETCHes the sort keys, and sorts locally. Feed `fallback` from a SORT
    /// capability check (the server SORT requires the extension).
    pub fn sort(
        &mut self,
        sort_criteria: Vec1<SortCriterion>,
        search_criteria: Vec1<SearchKey<'static>>,
        opts: ImapMessageSortOptions,
    ) -> Result<Vec<NonZeroU32>, ImapClientStdError> {
        self.run(ImapMessageSort::new(sort_criteria, search_criteria, opts))
    }

    /// `THREAD`; returns the message threads matching `search_criteria`.
    pub fn thread(
        &mut self,
        algorithm: ThreadingAlgorithm<'static>,
        search_criteria: Vec1<SearchKey<'static>>,
        opts: ImapMessageThreadOptions,
    ) -> Result<Vec<Thread>, ImapClientStdError> {
        self.run(ImapMessageThread::new(algorithm, search_criteria, opts))
    }
}

impl fmt::Debug for ImapClientStd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImapClientStd")
            .field("fragmentizer", &self.fragmentizer)
            .finish_non_exhaustive()
    }
}

/// Background-worker watch stream; drop or [`Self::close`] to wind down.
pub struct ImapMailboxWatchStream {
    rx: Receiver<Result<ImapMailboxWatchEvent, ImapClientStdError>>,
    handle: Option<JoinHandle<()>>,
    shutdown: Arc<AtomicBool>,
}

impl ImapMailboxWatchStream {
    /// Non-blocking probe for the next event.
    pub fn try_recv(
        &self,
    ) -> Result<Result<ImapMailboxWatchEvent, ImapClientStdError>, TryRecvError> {
        self.rx.try_recv()
    }

    /// Waits up to `timeout` for the next event.
    pub fn recv_timeout(
        &self,
        timeout: Duration,
    ) -> Result<Result<ImapMailboxWatchEvent, ImapClientStdError>, RecvTimeoutError> {
        self.rx.recv_timeout(timeout)
    }

    /// Signals shutdown and joins the worker.
    pub fn close(mut self) -> Result<(), ImapClientStdError> {
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
    type Item = Result<ImapMailboxWatchEvent, ImapClientStdError>;

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

#[cfg(any(
    feature = "rustls-aws",
    feature = "rustls-ring",
    feature = "native-tls"
))]
impl ImapClientStd {
    /// End-to-end connect: TCP/TLS, optional STARTTLS, greeting,
    /// optional SASL. `imap://` is plain TCP (143), `imaps://` is
    /// implicit TLS (993). `starttls = true` is only valid on
    /// `imap://`. Pass `Sasl::None` to skip auth.
    pub fn connect(
        url: &Url,
        tls: &Tls,
        starttls: bool,
        sasl: Option<impl Into<Sasl>>,
        auto_id: Option<Vec<(IString<'static>, NString<'static>)>>,
    ) -> Result<(Self, Vec<Capability<'static>>), ImapClientStdError> {
        let Some(host) = url.host_str() else {
            return Err(ImapClientStdError::UrlMissingHost(url.to_string()));
        };

        let (stream, is_tls) = match url.scheme() {
            scheme if scheme.eq_ignore_ascii_case("imap") => (
                StreamStd::connect_tcp(host, url.port().unwrap_or(143))?,
                false,
            ),
            scheme if scheme.eq_ignore_ascii_case("imaps") => (
                StreamStd::connect_tls(host, url.port().unwrap_or(993), tls)?,
                true,
            ),
            scheme => {
                let url = url.to_string();
                let scheme = scheme.to_string();
                return Err(ImapClientStdError::UrlUnsupportedScheme(url, scheme));
            }
        };

        if starttls && is_tls {
            return Err(ImapClientStdError::StartTlsOverTls);
        }

        // NOTE: STARTTLS needs the concrete StreamStd for upgrade_tls,
        // so run it inline before boxing the stream.
        let stream = if starttls {
            let mut stream = stream;
            let mut fragmentizer = Fragmentizer::new(FRAGMENTIZER_MAX_MESSAGE_SIZE);
            run_starttls(&mut stream, &mut fragmentizer)?;
            stream.upgrade_tls(tls)?
        } else {
            stream
        };

        // NOTE: 5s per-read timeout lets watch_mailbox poll shutdown
        // during a silent IDLE; long FETCHes are unaffected.
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;

        let mut client = Self::new(stream);
        client.auto_id = auto_id;

        let mut capability = if starttls {
            client.capability()?
        } else {
            client.greeting()?
        };

        if let Some(sasl) = sasl.map(Into::into) {
            let ir = capability.contains(&Capability::SaslIr);

            capability = match sasl {
                Sasl::Anonymous(SaslAnonymous { message }) => {
                    let opts = ImapAuthAnonymousOptions {
                        initial_request: ir,
                        ensure_capabilities: true,
                        auto_id: client.auto_id.take(),
                    };

                    client.auth_anonymous(message, opts)?
                }
                Sasl::Login(SaslLogin { username, password }) => {
                    let opts = ImapLoginOptions {
                        ensure_capabilities: true,
                        auto_id: client.auto_id.take(),
                    };

                    client.login(username, password.expose_secret(), opts)?
                }
                Sasl::Plain(SaslPlain {
                    authzid,
                    authcid,
                    passwd,
                }) => {
                    let opts = ImapAuthPlainOptions {
                        initial_request: ir,
                        ensure_capabilities: true,
                        auto_id: client.auto_id.take(),
                    };

                    client.auth_plain(authzid, authcid, passwd.expose_secret(), opts)?
                }
                Sasl::Oauthbearer(SaslOauthbearer {
                    username,
                    host,
                    port,
                    token,
                }) => {
                    let opts = ImapAuthOauthbearerOptions {
                        initial_request: ir,
                        ensure_capabilities: true,
                        auto_id: client.auto_id.take(),
                    };

                    client.auth_oauthbearer(username, host, port, token.expose_secret(), opts)?
                }
                Sasl::Xoauth2(SaslXoauth2 { username, token }) => {
                    let opts = ImapAuthXoauth2Options {
                        initial_request: ir,
                        ensure_capabilities: true,
                        auto_id: client.auto_id.take(),
                    };

                    client.auth_xoauth2(username, token.expose_secret(), opts)?
                }
                #[cfg(feature = "scram")]
                Sasl::ScramSha256(SaslScramSha256 { username, password }) => {
                    let opts = ImapAuthScramSha256Options {
                        initial_request: ir,
                        ensure_capabilities: true,
                        auto_id: client.auto_id.take(),
                    };

                    client.auth_scram_sha256(username, password.expose_secret(), opts)?
                }
                #[cfg(not(feature = "scram"))]
                Sasl::ScramSha256(_) => {
                    return Err(ImapClientStdError::ScramSha256NotEnabled);
                }
            };
        }

        Ok((client, capability))
    }
}

/// Inline STARTTLS driver: keeps the concrete `StreamStd` so that
/// `upgrade_tls` can swap the underlying socket afterwards.
#[cfg(any(
    feature = "rustls-aws",
    feature = "rustls-ring",
    feature = "native-tls"
))]
fn run_starttls(
    stream: &mut StreamStd,
    fragmentizer: &mut Fragmentizer,
) -> Result<(), ImapClientStdError> {
    let mut coroutine = ImapStartTls::new();
    let mut buf = [0u8; READ_BUFFER_SIZE];
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(fragmentizer, arg.take()) {
            ImapCoroutineState::Complete(Ok(_)) => return Ok(()),
            ImapCoroutineState::Complete(Err(err)) => return Err(err.into()),
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
                let n = stream.read(&mut buf)?;
                arg = Some(&buf[..n]);
            }
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
                stream.write_all(&bytes)?;
            }
        }
    }
}

/// Auto-implemented for `Read + Write + Send + 'static`. `as_any_mut` supports
/// downcasting back to the concrete stream when needed (e.g. for
/// `set_read_timeout`).
pub trait ImapStream: Read + Write + Send + Any {
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

impl<T: Read + Write + Send + Any> ImapStream for T {
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}
