//! # Standard, blocking IMAP client
//!
//! Holds a single stream (any blocking `Read + Write` impl) plus a
//! per-connection [`Fragmentizer`], and exposes one method per common
//! coroutine. The bare [`new`] constructor takes a pre-connected stream;
//! callers handle TCP and TLS themselves. With one of the TLS feature flags
//! enabled (`rustls-ring`, `rustls-aws`, `native-tls`), [`connect`] is also
//! available and produces a ready-to-use authenticated client end-to-end:
//! it opens the transport (plain TCP for `imap://`, implicit TLS for
//! `imaps://`), optionally performs the STARTTLS upgrade, reads the
//! greeting and capability list, then runs the chosen SASL mechanism if
//! one was provided.
//!
//! Session state (current mailbox, authenticated flag, cached
//! capability) is intentionally NOT stored on the client: it desyncs
//! too easily from server state. Methods that observe a fresh
//! capability list return it; callers that want a cached copy keep it
//! themselves.
//!
//! [`new`]: ImapClientStd::new
//! [`connect`]: ImapClientStd::connect

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
        datetime::DateTime,
        extensions::{
            binary::LiteralOrLiteral8,
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
        append::*, capability::*, check::*, close::*, copy::*, create::*, delete::*, examine::*,
        expunge::*, fetch::*, greeting::*, list::*, login::*, logout::*, lsub::*, noop::*,
        rename::*, search::*, select::*, starttls::*, status::*, store::*, subscribe::*,
        unsubscribe::*,
    },
    rfc3691::unselect::*,
    rfc5161::enable::*,
    rfc5256::{sort::*, thread::*},
    rfc6851::r#move::*,
    rfc7628::auth_oauthbearer::*,
    sasl::{auth_anonymous::*, auth_login::*, auth_plain::*, auth_xoauth2::*},
    watch::*,
};

/// Errors returned by [`ImapClientStd`].
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
    MailboxSort(#[from] ImapMailboxSortError),

    #[error(transparent)]
    MessageFetch(#[from] ImapMessageFetchError),
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

/// Default ALPN protocol identifier offered during the TLS handshake
/// for IMAP connections (RFC 7595 registers the `imap` token).
/// Re-exported so config-driven callers can use it as a serde default
/// and so wizard/discovery code shares a single source of truth.
pub fn default_alpn() -> Vec<String> {
    vec![String::from("imap")]
}

/// Std-blocking IMAP client wrapping a single boxed stream plus a
/// per-connection [`Fragmentizer`].
///
/// `auto_id` is the optional RFC 2971 payload sent by every auth_*/
/// login method straight after authentication: [`None`] skips the
/// extra round-trip (default); [`Some`] with an empty vec sends
/// `ID NIL`; [`Some`] with parameters sends `ID (key val …)`. Some
/// providers (notably mail.qq.com, fastmail) require an ID exchange
/// before they will accept further commands.
pub struct ImapClientStd {
    pub stream: Box<dyn ImapStream>,
    pub fragmentizer: Fragmentizer,
    pub auto_id: Option<Vec<(IString<'static>, NString<'static>)>>,
}

impl ImapClientStd {
    /// Builds a client around `stream`. The caller is responsible for
    /// opening the connection (TCP, TLS handshake if needed, STARTTLS
    /// upgrade if needed). `auto_id` defaults to [`None`]; set it on
    /// the returned client before invoking an auth_*/login method to
    /// chain an `ID` round-trip after the SASL handshake.
    pub fn new<S: Read + Write + Send + 'static>(stream: S) -> Self {
        Self {
            stream: Box::new(stream),
            fragmentizer: Fragmentizer::new(FRAGMENTIZER_MAX_MESSAGE_SIZE),
            auto_id: None,
        }
    }

    /// Replaces the underlying stream; useful after a STARTTLS upgrade
    /// or when the caller manages reconnection across hosts.
    pub fn set_stream<S: Read + Write + Send + 'static>(&mut self, stream: S) {
        self.stream = Box::new(stream);
    }

    /// Drives any standard-shape coroutine (`Yield = ImapYield`,
    /// `Return = Result<Output, Error>`) against this client's stream
    /// and fragmentizer until it terminates.
    ///
    /// Coroutines that need richer Yield variants
    /// ([`ImapStartTls`] with [`ImapStartTlsYield::WantsStartTls`],
    /// [`ImapIdle`](crate::rfc2177::idle::ImapIdle) with
    /// [`ImapIdleYield::Event`],
    /// [`ImapMailboxWatch`] with [`ImapMailboxWatchYield::Event`])
    /// are driven by their own per-method loops on this client; see
    /// [`Self::starttls`] and [`Self::watch_mailbox`].
    ///
    /// [`ImapStartTlsYield::WantsStartTls`]: crate::rfc3501::starttls::ImapStartTlsYield::WantsStartTls
    /// [`ImapIdleYield::Event`]: crate::rfc2177::idle::ImapIdleYield::Event
    /// [`ImapMailboxWatchYield::Event`]: crate::watch::ImapMailboxWatchYield::Event
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

    /// Runs [`ImapGreetingGet`] with `ensure_capabilities` set to `true`:
    /// consumes the initial server greeting and reports the capability
    /// list. Call this once after [`new`] / [`connect`].
    ///
    /// [`new`]: ImapClientStd::new
    /// [`connect`]: ImapClientStd::connect
    pub fn greeting(&mut self) -> Result<Vec<Capability<'static>>, ImapClientStdError> {
        Ok(self.run(ImapGreetingGet::new(true))?.capability)
    }

    /// Runs [`ImapLogin`] (`LOGIN`, RFC 3501 §6.2.3). The connection
    /// must be TLS-protected. Honours [`Self::auto_id`]: when set,
    /// chains an RFC 2971 `ID` round-trip after the tagged `OK`; the
    /// field is consumed and reset to [`None`].
    pub fn login(
        &mut self,
        user: impl AsRef<str>,
        password: impl AsRef<str>,
        opts: ImapLoginOptions,
    ) -> Result<Vec<Capability<'static>>, ImapClientStdError> {
        self.run(ImapLogin::new(user, password, opts)?)
    }

    /// Runs [`ImapStartTls`] (`STARTTLS`, RFC 3501 §6.2.1). The IMAP-layer
    /// handshake is complete on return; the caller must now upgrade the
    /// underlying socket to TLS (consume the client via [`into_stream`],
    /// call `upgrade_tls`, then rebuild a client) and refresh capabilities
    /// over the encrypted channel via [`capability`]. The returned bytes
    /// are anything the coroutine pre-read past the tagged response
    /// (normally empty per RFC 3501 §6.2.1; any pre-handshake bytes would
    /// be a classic STARTTLS-injection signal).
    ///
    /// [`into_stream`]: ImapClientStd::into_stream
    /// [`capability`]: ImapClientStd::capability
    pub fn starttls(&mut self) -> Result<Vec<u8>, ImapClientStdError> {
        let mut coroutine = ImapStartTls::new();
        let mut buf = [0u8; READ_BUFFER_SIZE];
        let mut arg: Option<&[u8]> = None;
        let mut remaining: Option<Vec<u8>> = None;

        loop {
            match coroutine.resume(&mut self.fragmentizer, arg.take()) {
                ImapCoroutineState::Complete(Ok(())) => {
                    return Ok(remaining.unwrap_or_default());
                }
                ImapCoroutineState::Complete(Err(err)) => return Err(err.into()),
                ImapCoroutineState::Yielded(ImapStartTlsYield::WantsRead) => {
                    let n = self.stream.read(&mut buf)?;
                    arg = Some(&buf[..n]);
                }
                ImapCoroutineState::Yielded(ImapStartTlsYield::WantsWrite(bytes)) => {
                    self.stream.write_all(&bytes)?;
                    arg = None;
                }
                ImapCoroutineState::Yielded(ImapStartTlsYield::WantsStartTls(bytes)) => {
                    remaining = Some(bytes);
                    arg = None;
                }
            }
        }
    }

    /// Runs [`ImapAuthAnonymous`] (SASL `AUTHENTICATE ANONYMOUS`, RFC
    /// 4505). `opts.initial_request` selects between the non-IR and
    /// SASL-IR (RFC 4959) flows. `message` is the optional trace
    /// identifier; pass `None` to omit it. Honours [`Self::auto_id`]
    /// (see [`login`] for details).
    ///
    /// [`login`]: ImapClientStd::login
    pub fn auth_anonymous(
        &mut self,
        message: Option<impl AsRef<str>>,
        opts: ImapAuthAnonymousOptions,
    ) -> Result<Vec<Capability<'static>>, ImapClientStdError> {
        self.run(ImapAuthAnonymous::new(message, opts))
    }

    /// Runs [`ImapAuthLogin`] (SASL `AUTHENTICATE LOGIN`, legacy
    /// two-prompt mechanism). `opts.initial_request` selects between
    /// the non-IR and SASL-IR (RFC 4959) flows. Prefer [`auth_plain`]
    /// or [`auth_scram_sha256`] when the server supports them. Honours
    /// [`Self::auto_id`].
    ///
    /// [`auth_plain`]: ImapClientStd::auth_plain
    /// [`auth_scram_sha256`]: ImapClientStd::auth_scram_sha256
    pub fn auth_login(
        &mut self,
        user: impl AsRef<str>,
        password: impl AsRef<str>,
        opts: ImapAuthLoginOptions,
    ) -> Result<Vec<Capability<'static>>, ImapClientStdError> {
        self.run(ImapAuthLogin::new(user, password, opts))
    }

    /// Runs [`ImapAuthPlain`] (SASL `AUTHENTICATE PLAIN`, RFC 4616).
    /// `opts.initial_request` selects between the non-IR and SASL-IR
    /// (RFC 4959) flows. Honours [`Self::auto_id`].
    pub fn auth_plain(
        &mut self,
        authzid: Option<impl AsRef<str>>,
        authcid: impl AsRef<str>,
        password: impl AsRef<str>,
        opts: ImapAuthPlainOptions,
    ) -> Result<Vec<Capability<'static>>, ImapClientStdError> {
        self.run(ImapAuthPlain::new(authzid, authcid, password, opts))
    }

    /// Runs [`ImapAuthOauthbearer`] (SASL `AUTHENTICATE OAUTHBEARER`,
    /// RFC 7628). `opts.initial_request` selects between the non-IR
    /// and SASL-IR (RFC 4959) flows. The `token` is an OAuth 2.0
    /// bearer access token: the connection must be TLS-protected
    /// before calling this method. Honours [`Self::auto_id`].
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

    /// Runs [`ImapAuthXoauth2`] (SASL `AUTHENTICATE XOAUTH2`, Google's
    /// pre-standard OAuth 2.0 mechanism). `opts.initial_request`
    /// selects between the non-IR and SASL-IR (RFC 4959) flows. The
    /// `token` is an OAuth 2.0 bearer access token: the connection
    /// must be TLS-protected. Prefer [`auth_oauthbearer`] on servers
    /// that support both. Honours [`Self::auto_id`].
    ///
    /// [`auth_oauthbearer`]: ImapClientStd::auth_oauthbearer
    pub fn auth_xoauth2(
        &mut self,
        user: impl AsRef<str>,
        token: impl AsRef<str>,
        opts: ImapAuthXoauth2Options,
    ) -> Result<Vec<Capability<'static>>, ImapClientStdError> {
        self.run(ImapAuthXoauth2::new(user, token, opts))
    }

    /// Runs [`ImapAuthScramSha256`] (SASL `AUTHENTICATE SCRAM-SHA-256`,
    /// RFC 7677). `opts.initial_request` selects between the non-IR
    /// and SASL-IR (RFC 4959) flows. Honours [`Self::auto_id`].
    #[cfg(feature = "scram")]
    pub fn auth_scram_sha256(
        &mut self,
        user: impl AsRef<str>,
        password: impl AsRef<str>,
        opts: ImapAuthScramSha256Options,
    ) -> Result<Vec<Capability<'static>>, ImapClientStdError> {
        self.run(ImapAuthScramSha256::new(user, password, opts))
    }

    /// Runs [`ImapLogout`] (`LOGOUT`).
    pub fn logout(&mut self) -> Result<(), ImapClientStdError> {
        self.run(ImapLogout::new())
    }

    // ---- State / introspection -------------------------------------------

    /// Runs [`ImapCapabilityGet`] (`CAPABILITY`).
    pub fn capability(&mut self) -> Result<Vec<Capability<'static>>, ImapClientStdError> {
        self.run(ImapCapabilityGet::new())
    }

    /// Runs [`ImapNoop`] (`NOOP`).
    pub fn noop(&mut self) -> Result<(), ImapClientStdError> {
        self.run(ImapNoop::new())
    }

    /// Runs [`ImapServerId`] (`ID`, RFC 2971). Pass [`None`] to send the
    /// empty-list `ID NIL` form.
    pub fn id(
        &mut self,
        parameters: Option<Vec<(IString<'static>, NString<'static>)>>,
    ) -> Result<Option<Vec<(IString<'static>, NString<'static>)>>, ImapClientStdError> {
        self.run(ImapServerId::new(ImapServerIdOptions { parameters }))
    }

    /// Runs [`ImapExtensionEnable`] (`ENABLE`, RFC 5161).
    pub fn enable(
        &mut self,
        capabilities: Vec1<CapabilityEnable<'static>>,
    ) -> Result<Option<Vec<CapabilityEnable<'static>>>, ImapClientStdError> {
        self.run(ImapExtensionEnable::new(capabilities))
    }

    // ---- Mailbox structure -----------------------------------------------

    /// Runs [`ImapMailboxList`] (`LIST <reference> <pattern>`).
    pub fn list(
        &mut self,
        reference: Mailbox<'static>,
        pattern: ListMailbox<'static>,
    ) -> Result<ImapMailboxListing, ImapClientStdError> {
        self.run(ImapMailboxList::new(reference, pattern))
    }

    /// Runs [`ImapMailboxLsub`] (`LSUB <reference> <pattern>`).
    pub fn lsub(
        &mut self,
        reference: Mailbox<'static>,
        pattern: ListMailbox<'static>,
    ) -> Result<ImapMailboxListing, ImapClientStdError> {
        self.run(ImapMailboxLsub::new(reference, pattern))
    }

    /// Runs [`ImapMailboxStatus`] (`STATUS <mailbox> <items>`).
    pub fn status(
        &mut self,
        mailbox: Mailbox<'static>,
        item_names: impl Into<Cow<'static, [StatusDataItemName]>>,
    ) -> Result<Vec<StatusDataItem>, ImapClientStdError> {
        self.run(ImapMailboxStatus::new(mailbox, item_names))
    }

    /// Runs [`ImapMailboxCreate`] (`CREATE <mailbox>`).
    pub fn create(&mut self, mailbox: Mailbox<'static>) -> Result<(), ImapClientStdError> {
        self.run(ImapMailboxCreate::new(mailbox))
    }

    /// Runs [`ImapMailboxDelete`] (`DELETE <mailbox>`).
    pub fn delete(&mut self, mailbox: Mailbox<'static>) -> Result<(), ImapClientStdError> {
        self.run(ImapMailboxDelete::new(mailbox))
    }

    /// Runs [`ImapMailboxRename`] (`RENAME <from> <to>`).
    pub fn rename(
        &mut self,
        from: Mailbox<'static>,
        to: Mailbox<'static>,
    ) -> Result<(), ImapClientStdError> {
        self.run(ImapMailboxRename::new(from, to))
    }

    /// Runs [`ImapMailboxSubscribe`] (`SUBSCRIBE <mailbox>`).
    pub fn subscribe(&mut self, mailbox: Mailbox<'static>) -> Result<(), ImapClientStdError> {
        self.run(ImapMailboxSubscribe::new(mailbox))
    }

    /// Runs [`ImapMailboxUnsubscribe`] (`UNSUBSCRIBE <mailbox>`).
    pub fn unsubscribe(&mut self, mailbox: Mailbox<'static>) -> Result<(), ImapClientStdError> {
        self.run(ImapMailboxUnsubscribe::new(mailbox))
    }

    // ---- Mailbox selection -----------------------------------------------

    /// Runs [`ImapMailboxSelect`] (`SELECT <mailbox>`).
    pub fn select(&mut self, mailbox: Mailbox<'static>) -> Result<SelectData, ImapClientStdError> {
        self.run(ImapMailboxSelect::new(mailbox))
    }

    /// Runs [`ImapMailboxExamine`] (`EXAMINE <mailbox>`).
    pub fn examine(&mut self, mailbox: Mailbox<'static>) -> Result<SelectData, ImapClientStdError> {
        self.run(ImapMailboxExamine::new(
            mailbox,
            ImapMailboxExamineOptions::default(),
        ))
    }

    /// Runs `SELECT <mailbox> (QRESYNC (<uidvalidity> <highestmodseq>))`
    /// (RFC 7162). The caller must have observed `QRESYNC` in the
    /// `capability` slice; otherwise this errors with
    /// [`ImapClientStdError::QresyncNotSupported`]. Errors with
    /// [`ImapClientStdError::InvalidModSeq`] when `highest_mod_seq` is
    /// 0.
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

        self.run(ImapMailboxSelect::with_parameters(mailbox, parameters))
    }

    /// Runs [`ImapMailboxClose`] (`CLOSE`).
    pub fn close(&mut self) -> Result<(), ImapClientStdError> {
        self.run(ImapMailboxClose::new())
    }

    /// Runs [`ImapMailboxUnselect`] (`UNSELECT`, RFC 3691).
    pub fn unselect(&mut self) -> Result<(), ImapClientStdError> {
        self.run(ImapMailboxUnselect::new())
    }

    /// Runs [`ImapMailboxCheck`] (`CHECK`).
    pub fn check(&mut self) -> Result<(), ImapClientStdError> {
        self.run(ImapMailboxCheck::new())
    }

    /// Runs [`ImapMailboxExpunge`] (`EXPUNGE`). Returns the sequence
    /// numbers of expunged messages.
    pub fn expunge(&mut self) -> Result<Vec<NonZeroU32>, ImapClientStdError> {
        self.run(ImapMailboxExpunge::new())
    }

    /// Consumes the client and starts a long-running mailbox watcher.
    ///
    /// Spawns a thread that owns the IMAP connection and advances the
    /// [`ImapMailboxWatch`] coroutine, forwarding each delta as one
    /// [`ImapMailboxWatchEvent`] on the returned stream's mpsc channel.
    /// Untagged-response wake-ups are resolved via SELECT (QRESYNC).  Dropping
    /// the stream (or calling [`ImapMailboxWatchStream::close`]) flips the
    /// shutdown atomic; the worker winds the running IDLE down cleanly and
    /// exits.
    ///
    /// `capability` is the most recently observed capability list; pass
    /// the slice returned by `greeting()` / `login()` / `auth_*()` or
    /// `capability()`. Errors with [`ImapClientStdError::MailboxWatch`]
    /// + `ImapMailboxWatchError::QresyncUnsupported` when QRESYNC is
    /// absent.
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

    /// Runs [`ImapMessageFetch`] (`FETCH` or `UID FETCH`).
    pub fn fetch(
        &mut self,
        sequence_set: SequenceSet,
        items: MacroOrMessageDataItemNames<'static>,
        uid: bool,
    ) -> Result<BTreeMap<NonZeroU32, Vec1<MessageDataItem<'static>>>, ImapClientStdError> {
        self.run(ImapMessageFetch::new(
            sequence_set,
            items,
            ImapMessageFetchOptions {
                uid,
                ..Default::default()
            },
        ))
    }

    /// Runs [`ImapMessageSearch`] (`SEARCH` or `UID SEARCH`).
    pub fn search(
        &mut self,
        criteria: Vec1<SearchKey<'static>>,
        uid: bool,
    ) -> Result<Vec<NonZeroU32>, ImapClientStdError> {
        self.run(ImapMessageSearch::new(criteria, uid))
    }

    /// Runs [`ImapMessageStore`] (`STORE` or `UID STORE`). Returns the
    /// updated message data items the server reported back.
    pub fn store(
        &mut self,
        sequence_set: SequenceSet,
        kind: StoreType,
        flags: Vec<Flag<'static>>,
        uid: bool,
    ) -> Result<BTreeMap<NonZeroU32, Vec1<MessageDataItem<'static>>>, ImapClientStdError> {
        self.run(ImapMessageStore::new(sequence_set, kind, flags, uid))
    }

    /// Runs [`ImapMessageCopy`] (`COPY` or `UID COPY`).
    pub fn copy(
        &mut self,
        sequence_set: SequenceSet,
        mailbox: Mailbox<'static>,
        uid: bool,
    ) -> Result<ImapCopyUid, ImapClientStdError> {
        self.run(ImapMessageCopy::new(
            sequence_set,
            mailbox,
            ImapMessageCopyOptions { uid },
        ))
    }

    /// Runs [`ImapMessageMove`] (`MOVE` or `UID MOVE`, RFC 6851).
    pub fn r#move(
        &mut self,
        sequence_set: SequenceSet,
        mailbox: Mailbox<'static>,
        uid: bool,
    ) -> Result<ImapCopyUid, ImapClientStdError> {
        self.run(ImapMessageMove::new(sequence_set, mailbox, uid))
    }

    /// Runs [`ImapMessageAppend`] (`APPEND <mailbox> [flags] [date]
    /// <message>`). Returns the optional `EXISTS` count and the
    /// `[APPENDUID uidvalidity uid]` response code (RFC 4315).
    pub fn append(
        &mut self,
        mailbox: Mailbox<'static>,
        flags: Vec<Flag<'static>>,
        date: Option<DateTime>,
        message: LiteralOrLiteral8<'static>,
    ) -> Result<ImapAppendOutput, ImapClientStdError> {
        self.run(ImapMessageAppend::new(
            mailbox,
            message,
            ImapMessageAppendOptions { flags, date },
        ))
    }

    // ---- RFC 5256: SORT / THREAD ------------------------------------------

    /// Runs [`ImapMailboxSort`] (`SORT` or `UID SORT`, RFC 5256).
    pub fn sort(
        &mut self,
        sort_criteria: Vec1<SortCriterion>,
        search_criteria: Vec1<SearchKey<'static>>,
        uid: bool,
    ) -> Result<Vec<NonZeroU32>, ImapClientStdError> {
        self.run(ImapMailboxSort::new(sort_criteria, search_criteria, uid))
    }

    /// Runs [`ImapMessageThread`] (`THREAD` or `UID THREAD`, RFC 5256).
    pub fn thread(
        &mut self,
        algorithm: ThreadingAlgorithm<'static>,
        search_criteria: Vec1<SearchKey<'static>>,
        uid: bool,
    ) -> Result<Vec<Thread>, ImapClientStdError> {
        self.run(ImapMessageThread::new(algorithm, search_criteria, uid))
    }
}

impl fmt::Debug for ImapClientStd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImapClientStd")
            .field("fragmentizer", &self.fragmentizer)
            .finish_non_exhaustive()
    }
}

/// Long-lived [`ImapMailboxWatchEvent`] stream backed by a background
/// worker thread that owns the IMAP connection. Drop or
/// [`Self::close`] to wind it down; the worker observes the shutdown
/// atomic, sends `IDLE DONE`, and exits.
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

    /// Signals the worker to stop and joins it. Returns within the
    /// IDLE refresh window (typically a few seconds).
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
    /// Connects to `url`, optionally performs the STARTTLS upgrade, reads
    /// the greeting + capability list, then runs the chosen SASL
    /// mechanism.
    ///
    /// - `imap://`  goes through plain TCP (port defaults to 143).
    /// - `imaps://` goes through implicit TLS (port defaults to 993).
    /// - `tls` carries the rustls/native-tls options *and* the ALPN list
    ///   (see [`default_alpn`] for the IMAP-conformant `["imap"]`).
    ///   Set `tls.rustls.alpn` to an empty vec to skip ALPN.
    /// - `starttls = true` (only valid on `imap://`) performs the IMAP
    ///   `STARTTLS` upgrade and refreshes capabilities over TLS before
    ///   authenticating.
    /// - `sasl` is the optional SASL mechanism. Accepts anything that
    ///   converts into a [`Sasl`], so callers can pass the per-mechanism
    ///   struct directly (e.g. `Some(SaslLogin { .. })`) without wrapping
    ///   it in a [`Sasl`] variant. Supported mechanisms: [`SaslLogin`]
    ///   (mapped to the IMAP `LOGIN` command, RFC 3501 §6.2.3),
    ///   [`SaslPlain`] (RFC 4616), [`SaslAnonymous`] (RFC 4505),
    ///   [`SaslOauthbearer`] (RFC 7628), [`SaslXoauth2`] (Google), and
    ///   [`SaslScramSha256`] (RFC 7677, behind the `scram` cargo
    ///   feature). Pass [`None`] to skip authentication.
    /// - `auto_id` is forwarded to the auth coroutine and triggers an
    ///   RFC 2971 `ID` exchange after authentication (see
    ///   [`Self::auto_id`]).
    ///
    /// Returns a fully authenticated client paired with the latest
    /// observed capability list, ready to issue further commands.
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

        // STARTTLS needs the concrete StreamStd to call upgrade_tls
        // after the IMAP-layer handshake; once boxed there is no way
        // back to the concrete type. Run the STARTTLS coroutine inline
        // against the raw stream + a temporary fragmentizer, swap in
        // the upgraded stream, then build the boxed client.
        let stream = if starttls {
            let mut stream = stream;
            let mut fragmentizer = Fragmentizer::new(FRAGMENTIZER_MAX_MESSAGE_SIZE);
            run_starttls(&mut stream, &mut fragmentizer)?;
            stream.upgrade_tls(tls)?
        } else {
            stream
        };

        // Sensible default read timeout: makes [`watch_mailbox`] poll
        // its shutdown flag every 5 s instead of blocking forever on
        // the silent IDLE socket. Per-read (not per-operation) so big
        // FETCH responses are unaffected as long as TCP packets keep
        // arriving.
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

/// Drives [`ImapStartTls`] inline against a concrete `StreamStd` +
/// `Fragmentizer`. Used by [`ImapClientStd::connect`] when the caller
/// asks for STARTTLS: the IMAP-layer handshake has to complete on the
/// plain socket before [`StreamStd::upgrade_tls`] can swap the stream,
/// and the boxed [`ImapClientStd::stream`] hides the concrete type
/// that `upgrade_tls` needs.
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
            ImapCoroutineState::Complete(Ok(())) => return Ok(()),
            ImapCoroutineState::Complete(Err(err)) => return Err(err.into()),
            ImapCoroutineState::Yielded(ImapStartTlsYield::WantsRead) => {
                let n = stream.read(&mut buf)?;
                arg = Some(&buf[..n]);
            }
            ImapCoroutineState::Yielded(ImapStartTlsYield::WantsWrite(bytes)) => {
                stream.write_all(&bytes)?;
            }
            ImapCoroutineState::Yielded(ImapStartTlsYield::WantsStartTls(_)) => {}
        }
    }
}

/// Marker for everything the client can run against; auto-implemented
/// for any blocking `Read + Write + Send + 'static` impl. The `Send`
/// supertrait flows the auto-trait through the `Box<dyn ImapStream>`
/// type erasure so `ImapClientStd` can travel between threads in
/// worker pools. [`as_any_mut`] lets specialized callers (e.g.
/// byte-level proxies that need [`StreamStd::set_read_timeout`])
/// downcast the boxed stream back to its concrete type.
///
/// [`as_any_mut`]: ImapStream::as_any_mut
/// [`StreamStd::set_read_timeout`]: pimalaya_stream::std::stream::StreamStd::set_read_timeout
pub trait ImapStream: Read + Write + Send + Any {
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

impl<T: Read + Write + Send + Any> ImapStream for T {
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}
