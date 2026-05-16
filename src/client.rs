//! # Standard, blocking IMAP client
//!
//! Holds a single stream (any blocking `Read + Write` impl) plus the
//! long-lived [`ImapContext`], and exposes one method per common coroutine.
//! The bare [`new`] constructor takes a pre-connected stream; callers handle
//! TCP and TLS themselves. With one of the TLS feature flags enabled
//! (`rustls-ring`, `rustls-aws`, `native-tls`), [`connect`] is also available
//! and produces a ready-to-use authenticated client end-to-end: it opens the
//! transport (plain TCP for `imap://`, implicit TLS for `imaps://`),
//! optionally performs the STARTTLS upgrade, reads the greeting and capability
//! list, then runs the chosen SASL mechanism if one was provided.
//!
//! [`new`]: ImapClientStd::new
//! [`connect`]: ImapClientStd::connect

#[cfg(any(
    feature = "rustls-aws",
    feature = "rustls-ring",
    feature = "native-tls"
))]
use std::string::{String, ToString};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    num::NonZeroU32,
    vec::Vec,
};

use imap_codec::imap_types::{
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
    context::ImapContext,
    rfc2971::id::*,
    rfc3501::{
        append::*, capability::*, check::*, close::*, copy::*, create::*, delete::*, expunge::*,
        fetch::*, greeting::*, list::*, login::*, logout::*, lsub::*, noop::*, rename::*,
        search::*, select::*, starttls::*, status::*, store::*, subscribe::*, unsubscribe::*,
    },
    rfc3691::unselect::*,
    rfc5161::enable::*,
    rfc5256::{sort::*, thread::*},
    rfc6851::r#move::*,
    rfc7628::{auth_oauthbearer::*, auth_xoauth2::*},
    sasl::{auth_anonymous::*, auth_login::*, auth_plain::*},
};

const READ_BUFFER_SIZE: usize = 16 * 1024;

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
    AuthOAuthBearer(#[from] ImapAuthOAuthBearerError),
    #[error(transparent)]
    AuthXOAuth2(#[from] ImapAuthXOAuth2Error),
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
    Io(#[from] std::io::Error),
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

    #[error("IMAP client missing context (poisoned by a prior error)")]
    MissingContext,
}

/// Std-blocking IMAP client wrapping a single `Read + Write` stream
/// plus the long-lived [`ImapContext`].
pub struct ImapClientStd<S: Read + Write> {
    stream: S,
    context: Option<ImapContext>,
}

/// Run a coroutine to completion against `$self.stream`. The destructure
/// pattern names whichever payload fields of the `Ok` variant the caller wants;
/// `context` is bound and restored automatically. `$ret` is the expression
/// returned on success. Defaults to `{ .. } => ()` when the destructure /
/// return clause is omitted.
macro_rules! coroutine {
    ($self:ident, $coroutine:expr, $Result:ident) => {
        coroutine!($self, $coroutine, $Result, { .. } => ())
    };
    ($self:ident, $coroutine:expr, $Result:ident, { $($field:tt)* } => $ret:expr) => {{
        let mut buf = [0u8; READ_BUFFER_SIZE];
        let mut arg = None;
        let mut coroutine = $coroutine;

        loop {
            match coroutine.resume(arg) {
                $Result::Ok { context, $($field)* } => {
                    $self.context = Some(context);
                    return Ok($ret);
                }
                $Result::WantsRead => {
                    let n = $self.stream.read(&mut buf)?;
                    arg = Some(&buf[..n]);
                }
                $Result::WantsWrite(bytes) => {
                    $self.stream.write_all(&bytes)?;
                    arg = None;
                }
                $Result::Err { context, err } => {
                    $self.context = Some(context);
                    return Err(err.into());
                }
            }
        }
    }};
}

impl<S: Read + Write> ImapClientStd<S> {
    /// Builds a client around `stream` with a fresh [`ImapContext`]. The caller
    /// is responsible for opening the connection (TCP, TLS handshake if needed,
    /// STARTTLS upgrade if needed). Pair with [`with_context`] when bringing
    /// over an already-progressed session.
    ///
    /// [`with_context`]: ImapClientStd::with_context
    pub fn new(stream: S) -> Self {
        Self::with_context(stream, ImapContext::new())
    }

    /// Builds a client around `stream` and adopts `context` as its inner state.
    /// Useful when handing the stream off post-greeting / post-auth: the caller
    /// runs the early coroutines, then transfers the resulting context into
    /// the client.
    pub fn with_context(stream: S, context: ImapContext) -> Self {
        Self {
            stream,
            context: Some(context),
        }
    }

    /// Returns the current session context, if any.
    pub fn context(&self) -> Option<&ImapContext> {
        self.context.as_ref()
    }

    /// Returns a shared reference to the underlying stream.
    pub fn stream(&self) -> &S {
        &self.stream
    }

    /// Returns an exclusive reference to the underlying stream.
    pub fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Consumes the client and returns its underlying stream plus the inner
    /// context (if still present). Useful after [`starttls`] to perform a TLS
    /// upgrade on the raw stream before rebuilding a fresh client around the
    /// upgraded stream while preserving the negotiated context.
    ///
    /// [`starttls`]: ImapClientStd::starttls
    pub fn into_parts(self) -> (S, Option<ImapContext>) {
        (self.stream, self.context)
    }

    fn take_context(&mut self) -> Result<ImapContext, ImapClientStdError> {
        self.context
            .take()
            .ok_or(ImapClientStdError::MissingContext)
    }

    // ---- Session lifecycle ------------------------------------------------

    /// Runs [`ImapGreetingGet`] with `ensure_capabilities` set to `true`:
    /// consumes the initial server greeting and populates the capability list.
    /// Call this once after [`new`] / [`connect`]. Returns the freshly
    /// negotiated capability list.
    ///
    /// [`new`]: ImapClientStd::new
    /// [`connect`]: ImapClientStd::connect
    pub fn greeting(&mut self) -> Result<&[Capability<'static>], ImapClientStdError> {
        let context = self.take_context()?;
        coroutine!(
            self,
            ImapGreetingGet::new(context, true),
            ImapGreetingGetResult,
            { .. } => self.context.as_ref().unwrap().capability.as_slice()
        );
    }

    /// Runs [`ImapLogin`] (`LOGIN`) with the `ensure_capabilities` flag set
    /// so the capability list is always refreshed before returning.
    pub fn login(
        &mut self,
        params: ImapLoginParams,
    ) -> Result<&[Capability<'static>], ImapClientStdError> {
        let context = self.take_context()?;
        coroutine!(
            self,
            ImapLogin::new(context, params, true),
            ImapLoginResult,
            { .. } => self.context.as_ref().unwrap().capability.as_slice()
        );
    }

    /// Runs [`ImapStartTls`] (`STARTTLS`, RFC 3501 §6.2.1). The IMAP-layer
    /// handshake is complete on return; the caller must now upgrade the
    /// underlying socket to TLS (consume the client via [`into_parts`], call
    /// `upgrade_tls`, then rebuild a client with [`with_context`]) and refresh
    /// capabilities over the encrypted channel via [`capability`]. The
    /// returned bytes are anything the coroutine pre-read past the tagged
    /// response (normally empty per RFC 3501 §6.2.1; any pre-handshake bytes
    /// would be a classic STARTTLS-injection signal).
    ///
    /// [`into_parts`]: ImapClientStd::into_parts
    /// [`with_context`]: ImapClientStd::with_context
    /// [`capability`]: ImapClientStd::capability
    pub fn starttls(&mut self) -> Result<Vec<u8>, ImapClientStdError> {
        let context = self.take_context()?;
        let mut coroutine = ImapStartTls::new(context);
        let mut buf = [0u8; READ_BUFFER_SIZE];
        let mut arg: Option<&[u8]> = None;

        loop {
            match coroutine.resume(arg) {
                ImapStartTlsResult::WantsStartTls { context, remaining } => {
                    self.context = Some(context);
                    return Ok(remaining);
                }
                ImapStartTlsResult::WantsRead => {
                    let n = self.stream.read(&mut buf)?;
                    arg = Some(&buf[..n]);
                }
                ImapStartTlsResult::WantsWrite(bytes) => {
                    self.stream.write_all(&bytes)?;
                    arg = None;
                }
                ImapStartTlsResult::Err { context, err } => {
                    self.context = Some(context);
                    return Err(err.into());
                }
            }
        }
    }

    /// Runs [`ImapAuthAnonymous`] (SASL `AUTHENTICATE ANONYMOUS`, RFC 4505)
    /// with `ensure_capabilities=true` so the capability list is refreshed
    /// before returning.
    pub fn auth_anonymous(
        &mut self,
        params: ImapAuthAnonymousParams,
    ) -> Result<&[Capability<'static>], ImapClientStdError> {
        let context = self.take_context()?;
        coroutine!(
            self,
            ImapAuthAnonymous::new(context, params, true),
            ImapAuthAnonymousResult,
            { .. } => self.context.as_ref().unwrap().capability.as_slice()
        );
    }

    /// Runs [`ImapAuthLogin`] (SASL `AUTHENTICATE LOGIN`, legacy two-prompt
    /// mechanism) with `ensure_capabilities=true`. Prefer [`auth_plain`] or
    /// [`auth_scram_sha256`] when the server supports them.
    ///
    /// [`auth_plain`]: ImapClientStd::auth_plain
    /// [`auth_scram_sha256`]: ImapClientStd::auth_scram_sha256
    pub fn auth_login(
        &mut self,
        params: ImapAuthLoginParams,
    ) -> Result<&[Capability<'static>], ImapClientStdError> {
        let context = self.take_context()?;
        coroutine!(
            self,
            ImapAuthLogin::new(context, params, true),
            ImapAuthLoginResult,
            { .. } => self.context.as_ref().unwrap().capability.as_slice()
        );
    }

    /// Runs [`ImapAuthPlain`] (SASL `AUTHENTICATE PLAIN`, RFC 4616) with
    /// `ensure_capabilities=true`.
    pub fn auth_plain(
        &mut self,
        params: ImapAuthPlainParams,
    ) -> Result<&[Capability<'static>], ImapClientStdError> {
        let context = self.take_context()?;
        coroutine!(
            self,
            ImapAuthPlain::new(context, params, true),
            ImapAuthPlainResult,
            { .. } => self.context.as_ref().unwrap().capability.as_slice()
        );
    }

    /// Runs [`ImapAuthOAuthBearer`] (SASL `AUTHENTICATE OAUTHBEARER`,
    /// RFC 7628) with `ensure_capabilities=true`. The `token` is an OAuth 2.0
    /// bearer access token: the connection **must** be TLS-protected before
    /// calling this method.
    pub fn auth_oauthbearer(
        &mut self,
        params: ImapAuthOAuthBearerParams,
    ) -> Result<&[Capability<'static>], ImapClientStdError> {
        let context = self.take_context()?;
        coroutine!(
            self,
            ImapAuthOAuthBearer::new(context, params, true),
            ImapAuthOAuthBearerResult,
            { .. } => self.context.as_ref().unwrap().capability.as_slice()
        );
    }

    /// Runs [`ImapAuthXOAuth2`] (SASL `AUTHENTICATE XOAUTH2`, Google's
    /// pre-standard OAuth 2.0 mechanism) with `ensure_capabilities=true`. The
    /// `token` is an OAuth 2.0 bearer access token: the connection **must**
    /// be TLS-protected. Prefer [`auth_oauthbearer`] on servers that support
    /// both.
    ///
    /// [`auth_oauthbearer`]: ImapClientStd::auth_oauthbearer
    pub fn auth_xoauth2(
        &mut self,
        params: ImapAuthXOAuth2Params,
    ) -> Result<&[Capability<'static>], ImapClientStdError> {
        let context = self.take_context()?;
        coroutine!(
            self,
            ImapAuthXOAuth2::new(context, params, true),
            ImapAuthXOAuth2Result,
            { .. } => self.context.as_ref().unwrap().capability.as_slice()
        );
    }

    /// Runs [`ImapAuthScramSha256`] (SASL `AUTHENTICATE SCRAM-SHA-256`,
    /// RFC 7677) with `ensure_capabilities=true`.
    #[cfg(feature = "scram")]
    pub fn auth_scram_sha256(
        &mut self,
        params: ImapAuthScramSha256Params,
    ) -> Result<&[Capability<'static>], ImapClientStdError> {
        let context = self.take_context()?;
        coroutine!(
            self,
            ImapAuthScramSha256::new(context, params, true),
            ImapAuthScramSha256Result,
            { .. } => self.context.as_ref().unwrap().capability.as_slice()
        );
    }

    /// Runs [`ImapLogout`] (`LOGOUT`). Drops the session context after
    /// a successful logout; subsequent calls return
    /// [`ImapClientStdError::MissingContext`].
    pub fn logout(&mut self) -> Result<(), ImapClientStdError> {
        let context = self.take_context()?;
        let mut coroutine = ImapLogout::new(context);
        let mut buf = [0u8; READ_BUFFER_SIZE];
        let mut arg: Option<&[u8]> = None;

        loop {
            match coroutine.resume(arg) {
                ImapLogoutResult::Ok { .. } => return Ok(()),
                ImapLogoutResult::WantsRead => {
                    let n = self.stream.read(&mut buf)?;
                    arg = Some(&buf[..n]);
                }
                ImapLogoutResult::WantsWrite(bytes) => {
                    self.stream.write_all(&bytes)?;
                    arg = None;
                }
                ImapLogoutResult::Err { context, err } => {
                    self.context = Some(context);
                    return Err(err.into());
                }
            }
        }
    }

    // ---- State / introspection -------------------------------------------

    /// Runs [`ImapCapabilityGet`] (`CAPABILITY`). Returns the refreshed
    /// capability list.
    pub fn capability(&mut self) -> Result<&[Capability<'static>], ImapClientStdError> {
        let context = self.take_context()?;
        coroutine!(
            self,
            ImapCapabilityGet::new(context),
            ImapCapabilityGetResult,
            { .. } => self.context.as_ref().unwrap().capability.as_slice()
        );
    }

    /// Runs [`ImapNoop`] (`NOOP`). Any untagged updates the server pushes back
    /// are applied to the inner [`ImapContext`]; inspect via [`context`].
    ///
    /// [`context`]: ImapClientStd::context
    pub fn noop(&mut self) -> Result<(), ImapClientStdError> {
        let context = self.take_context()?;
        coroutine!(self, ImapNoop::new(context), ImapNoopResult);
    }

    /// Runs [`ImapServerId`] (`ID`, RFC 2971). Pass [`None`] to send the
    /// empty-list `ID NIL` form.
    pub fn id(
        &mut self,
        parameters: Option<Vec<(IString<'static>, NString<'static>)>>,
    ) -> Result<Option<Vec<(IString<'static>, NString<'static>)>>, ImapClientStdError> {
        let context = self.take_context()?;
        coroutine!(
            self,
            ImapServerId::new(context, parameters),
            ImapServerIdResult,
            { server_id, .. } => server_id
        );
    }

    /// Runs [`ImapExtensionEnable`] (`ENABLE`, RFC 5161).
    pub fn enable(
        &mut self,
        capabilities: Vec1<CapabilityEnable<'static>>,
    ) -> Result<Option<Vec<CapabilityEnable<'static>>>, ImapClientStdError> {
        let context = self.take_context()?;
        coroutine!(
            self,
            ImapExtensionEnable::new(context, capabilities),
            ImapExtensionEnableResult,
            { enabled, .. } => enabled
        );
    }

    // ---- Mailbox structure -----------------------------------------------

    /// Runs [`ImapMailboxList`] (`LIST <reference> <pattern>`).
    pub fn list(
        &mut self,
        reference: Mailbox<'static>,
        pattern: ListMailbox<'static>,
    ) -> Result<ImapMailboxListing, ImapClientStdError> {
        let context = self.take_context()?;
        coroutine!(
            self,
            ImapMailboxList::new(context, reference, pattern),
            ImapMailboxListResult,
            { mailboxes, .. } => mailboxes
        );
    }

    /// Runs [`ImapMailboxLsub`] (`LSUB <reference> <pattern>`).
    pub fn lsub(
        &mut self,
        reference: Mailbox<'static>,
        pattern: ListMailbox<'static>,
    ) -> Result<ImapMailboxListing, ImapClientStdError> {
        let context = self.take_context()?;
        coroutine!(
            self,
            ImapMailboxLsub::new(context, reference, pattern),
            ImapMailboxLsubResult,
            { mailboxes, .. } => mailboxes
        );
    }

    /// Runs [`ImapMailboxStatus`] (`STATUS <mailbox> <items>`).
    pub fn status(
        &mut self,
        mailbox: Mailbox<'static>,
        item_names: impl Into<alloc::borrow::Cow<'static, [StatusDataItemName]>>,
    ) -> Result<Vec<StatusDataItem>, ImapClientStdError> {
        let context = self.take_context()?;
        coroutine!(
            self,
            ImapMailboxStatus::new(context, mailbox, item_names),
            ImapMailboxStatusResult,
            { items, .. } => items
        );
    }

    /// Runs [`ImapMailboxCreate`] (`CREATE <mailbox>`).
    pub fn create(&mut self, mailbox: Mailbox<'static>) -> Result<(), ImapClientStdError> {
        let context = self.take_context()?;
        coroutine!(
            self,
            ImapMailboxCreate::new(context, mailbox),
            ImapMailboxCreateResult
        );
    }

    /// Runs [`ImapMailboxDelete`] (`DELETE <mailbox>`).
    pub fn delete(&mut self, mailbox: Mailbox<'static>) -> Result<(), ImapClientStdError> {
        let context = self.take_context()?;
        coroutine!(
            self,
            ImapMailboxDelete::new(context, mailbox),
            ImapMailboxDeleteResult
        );
    }

    /// Runs [`ImapMailboxRename`] (`RENAME <from> <to>`).
    pub fn rename(
        &mut self,
        from: Mailbox<'static>,
        to: Mailbox<'static>,
    ) -> Result<(), ImapClientStdError> {
        let context = self.take_context()?;
        coroutine!(
            self,
            ImapMailboxRename::new(context, from, to),
            ImapMailboxRenameResult
        );
    }

    /// Runs [`ImapMailboxSubscribe`] (`SUBSCRIBE <mailbox>`).
    pub fn subscribe(&mut self, mailbox: Mailbox<'static>) -> Result<(), ImapClientStdError> {
        let context = self.take_context()?;
        coroutine!(
            self,
            ImapMailboxSubscribe::new(context, mailbox),
            ImapMailboxSubscribeResult
        );
    }

    /// Runs [`ImapMailboxUnsubscribe`] (`UNSUBSCRIBE <mailbox>`).
    pub fn unsubscribe(&mut self, mailbox: Mailbox<'static>) -> Result<(), ImapClientStdError> {
        let context = self.take_context()?;
        coroutine!(
            self,
            ImapMailboxUnsubscribe::new(context, mailbox),
            ImapMailboxUnsubscribeResult
        );
    }

    // ---- Mailbox selection -----------------------------------------------

    /// Runs [`ImapMailboxSelect`] (`SELECT <mailbox>`).
    pub fn select(&mut self, mailbox: Mailbox<'static>) -> Result<SelectData, ImapClientStdError> {
        let context = self.take_context()?;
        coroutine!(
            self,
            ImapMailboxSelect::new(context, mailbox),
            ImapMailboxSelectResult,
            { data, .. } => data
        );
    }

    /// Runs [`ImapMailboxSelect::read_only`] (`EXAMINE <mailbox>`).
    pub fn examine(&mut self, mailbox: Mailbox<'static>) -> Result<SelectData, ImapClientStdError> {
        let context = self.take_context()?;
        coroutine!(
            self,
            ImapMailboxSelect::read_only(context, mailbox),
            ImapMailboxSelectResult,
            { data, .. } => data
        );
    }

    /// Runs [`ImapMailboxClose`] (`CLOSE`).
    pub fn close(&mut self) -> Result<(), ImapClientStdError> {
        let context = self.take_context()?;
        coroutine!(self, ImapMailboxClose::new(context), ImapMailboxCloseResult);
    }

    /// Runs [`ImapMailboxUnselect`] (`UNSELECT`, RFC 3691).
    pub fn unselect(&mut self) -> Result<(), ImapClientStdError> {
        let context = self.take_context()?;
        coroutine!(
            self,
            ImapMailboxUnselect::new(context),
            ImapMailboxUnselectResult
        );
    }

    /// Runs [`ImapMailboxCheck`] (`CHECK`).
    pub fn check(&mut self) -> Result<(), ImapClientStdError> {
        let context = self.take_context()?;
        coroutine!(self, ImapMailboxCheck::new(context), ImapMailboxCheckResult);
    }

    /// Runs [`ImapMailboxExpunge`] (`EXPUNGE`). Returns the sequence numbers
    /// of expunged messages.
    pub fn expunge(&mut self) -> Result<Vec<NonZeroU32>, ImapClientStdError> {
        let context = self.take_context()?;
        coroutine!(
            self,
            ImapMailboxExpunge::new(context),
            ImapMailboxExpungeResult,
            { expunged, .. } => expunged
        );
    }

    // ---- Messages --------------------------------------------------------

    /// Runs [`ImapMessageFetch`] (`FETCH` or `UID FETCH`).
    pub fn fetch(
        &mut self,
        sequence_set: SequenceSet,
        items: MacroOrMessageDataItemNames<'static>,
        uid: bool,
    ) -> Result<BTreeMap<NonZeroU32, Vec1<MessageDataItem<'static>>>, ImapClientStdError> {
        let context = self.take_context()?;
        coroutine!(
            self,
            ImapMessageFetch::new(context, sequence_set, items, uid),
            ImapMessageFetchResult,
            { data, .. } => data
        );
    }

    /// Runs [`ImapMessageSearch`] (`SEARCH` or `UID SEARCH`).
    pub fn search(
        &mut self,
        criteria: Vec1<SearchKey<'static>>,
        uid: bool,
    ) -> Result<Vec<NonZeroU32>, ImapClientStdError> {
        let context = self.take_context()?;
        coroutine!(
            self,
            ImapMessageSearch::new(context, criteria, uid),
            ImapMessageSearchResult,
            { ids, .. } => ids
        );
    }

    /// Runs [`ImapMessageStore`] (`STORE` or `UID STORE`). Returns the updated
    /// message data items the server reported back.
    pub fn store(
        &mut self,
        sequence_set: SequenceSet,
        kind: StoreType,
        flags: Vec<Flag<'static>>,
        uid: bool,
    ) -> Result<BTreeMap<NonZeroU32, Vec1<MessageDataItem<'static>>>, ImapClientStdError> {
        let context = self.take_context()?;
        coroutine!(
            self,
            ImapMessageStore::new(context, sequence_set, kind, flags, uid),
            ImapMessageStoreResult,
            { data, .. } => data
        );
    }

    /// Runs [`ImapMessageCopy`] (`COPY` or `UID COPY`).
    pub fn copy(
        &mut self,
        sequence_set: SequenceSet,
        mailbox: Mailbox<'static>,
        uid: bool,
    ) -> Result<ImapCopyUid, ImapClientStdError> {
        let context = self.take_context()?;
        coroutine!(
            self,
            ImapMessageCopy::new(context, sequence_set, mailbox, uid),
            ImapMessageCopyResult,
            { copyuid, .. } => copyuid
        );
    }

    /// Runs [`ImapMessageMove`] (`MOVE` or `UID MOVE`, RFC 6851).
    pub fn r#move(
        &mut self,
        sequence_set: SequenceSet,
        mailbox: Mailbox<'static>,
        uid: bool,
    ) -> Result<ImapCopyUid, ImapClientStdError> {
        let context = self.take_context()?;
        coroutine!(
            self,
            ImapMessageMove::new(context, sequence_set, mailbox, uid),
            ImapMessageMoveResult,
            { copyuid, .. } => copyuid
        );
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
        let context = self.take_context()?;
        coroutine!(
            self,
            ImapMessageAppend::new(context, mailbox, flags, date, message),
            ImapMessageAppendResult,
            { exists, appenduid, .. } => (exists, appenduid)
        );
    }

    // ---- RFC 5256: SORT / THREAD ------------------------------------------

    /// Runs [`ImapMailboxSort`] (`SORT` or `UID SORT`, RFC 5256).
    pub fn sort(
        &mut self,
        sort_criteria: Vec1<SortCriterion>,
        search_criteria: Vec1<SearchKey<'static>>,
        uid: bool,
    ) -> Result<Vec<NonZeroU32>, ImapClientStdError> {
        let context = self.take_context()?;
        coroutine!(
            self,
            ImapMailboxSort::new(context, sort_criteria, search_criteria, uid),
            ImapMailboxSortResult,
            { ids, .. } => ids
        );
    }

    /// Runs [`ImapMessageThread`] (`THREAD` or `UID THREAD`, RFC 5256).
    pub fn thread(
        &mut self,
        algorithm: ThreadingAlgorithm<'static>,
        search_criteria: Vec1<SearchKey<'static>>,
        uid: bool,
    ) -> Result<Vec<Thread>, ImapClientStdError> {
        let context = self.take_context()?;
        coroutine!(
            self,
            ImapMessageThread::new(context, algorithm, search_criteria, uid),
            ImapMessageThreadResult,
            { threads, .. } => threads
        );
    }
}

#[cfg(any(
    feature = "rustls-aws",
    feature = "rustls-ring",
    feature = "native-tls"
))]
impl ImapClientStd<StreamStd> {
    /// Connects to `url`, optionally performs the STARTTLS upgrade, reads the
    /// greeting + capability list, then runs the chosen SASL mechanism.
    ///
    /// - `imap://`  goes through plain TCP (port defaults to 143).
    /// - `imaps://` goes through implicit TLS (port defaults to 993).
    /// - `starttls = true` (only valid on `imap://`) performs the IMAP
    ///   `STARTTLS` upgrade and refreshes capabilities over TLS before
    ///   authenticating.
    /// - `sasl` is the optional SASL mechanism. Accepts anything that converts
    ///   into a [`Sasl`], so callers can pass the per-mechanism struct
    ///   directly (e.g. `Some(SaslLogin { .. })`) without wrapping it in a
    ///   [`Sasl`] variant. Supported mechanisms: [`SaslLogin`] (mapped to
    ///   the IMAP `LOGIN` command, RFC 3501 §6.2.3), [`SaslPlain`] (RFC
    ///   4616), [`SaslAnonymous`] (RFC 4505), [`SaslOauthbearer`] (RFC
    ///   7628), [`SaslXoauth2`] (Google), and [`SaslScramSha256`] (RFC
    ///   7677, behind the `scram` cargo feature). Pass [`None`] to skip
    ///   authentication.
    ///
    /// Returns a fully authenticated client ready to issue further
    /// commands.
    pub fn connect(
        url: &Url,
        tls: &Tls,
        starttls: bool,
        sasl: Option<impl Into<Sasl>>,
    ) -> Result<Self, ImapClientStdError> {
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

        let mut client = Self::new(stream);

        if starttls {
            client.starttls()?;
            let (raw, context) = client.into_parts();
            let upgraded = raw.upgrade_tls(tls)?;
            client = Self::with_context(upgraded, context.unwrap_or_else(ImapContext::new));
            client.capability()?;
        } else {
            client.greeting()?;
        }

        if let Some(sasl) = sasl.map(Into::into) {
            let ir = client
                .context()
                .map(|ctx| ctx.capability.contains(&Capability::SaslIr))
                .unwrap_or(false);

            match sasl {
                Sasl::Anonymous(SaslAnonymous { message }) => {
                    let params = ImapAuthAnonymousParams::new(message.unwrap_or_default(), ir);
                    client.auth_anonymous(params)?;
                }
                Sasl::Login(SaslLogin { username, password }) => {
                    let params = ImapLoginParams::new(username, password)?;
                    client.login(params)?;
                }
                Sasl::Plain(SaslPlain {
                    authzid,
                    authcid,
                    passwd,
                }) => {
                    let params = ImapAuthPlainParams::new(authzid, authcid, passwd, ir);
                    client.auth_plain(params)?;
                }
                Sasl::Oauthbearer(SaslOauthbearer {
                    username,
                    host,
                    port,
                    token,
                }) => {
                    let params = ImapAuthOAuthBearerParams::new(username, host, port, token, ir);
                    client.auth_oauthbearer(params)?;
                }
                Sasl::Xoauth2(SaslXoauth2 { username, token }) => {
                    let params = ImapAuthXOAuth2Params::new(username, token, ir);
                    client.auth_xoauth2(params)?;
                }
                #[cfg(feature = "scram")]
                Sasl::ScramSha256(SaslScramSha256 { username, password }) => {
                    let params = ImapAuthScramSha256Params::new(username, password, ir);
                    client.auth_scram_sha256(params)?;
                }
                #[cfg(not(feature = "scram"))]
                Sasl::ScramSha256(_) => {
                    return Err(ImapClientStdError::ScramSha256NotEnabled);
                }
            }
        }

        Ok(client)
    }
}
