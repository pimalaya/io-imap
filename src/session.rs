//! Composite session-opening coroutine: everything between a bare
//! address and an authenticated IMAP session.
//!
//! The handshake is where the protocol knowledge accumulates: which
//! transport a scheme implies, that the greeting precedes STARTTLS, that
//! CAPABILITY must be re-issued after the upgrade, that a PREAUTH
//! greeting means authentication is already done, whether the RFC 4959
//! initial response may be inlined, and which providers lie about it.
//! Holding all of that in a std client would put it out of reach of
//! every other runtime, so it lives here as a coroutine instead.
//!
//! Unlike a command coroutine, [`ImapSessionOpen`] yields transport
//! requests as well as reads and writes: connect this socket, upgrade
//! that one to TLS. The caller answers them with whatever sockets its
//! runtime has, and inherits the ordering and the provider quirks for
//! free. A caller that skips a step cannot advance, because the state
//! machine never asks for the next one.
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
//!     codec::fragmentizer::Fragmentizer,
//!     coroutine::{ImapCoroutine, ImapCoroutineState},
//!     session::{ImapSessionOpen, ImapSessionOpenOptions, ImapSessionOpenYield, ImapSessionTransport},
//! };
//! use pimalaya_stream::sasl::SaslPlain;
//!
//! let transport = ImapSessionTransport::Tcp {
//!     host: String::from("localhost"),
//!     port: 143,
//! };
//!
//! let sasl = SaslPlain {
//!     authzid: None,
//!     authcid: String::from("alice"),
//!     passwd: String::from("secret").into(),
//! };
//!
//! let mut coroutine = ImapSessionOpen::new(transport, Some(sasl), ImapSessionOpenOptions::default());
//! let mut fragmentizer = Fragmentizer::new(50 * 1024 * 1024);
//! let mut stream: Option<TcpStream> = None;
//! let mut buf = [0u8; 4096];
//! let mut arg = None;
//!
//! let session = loop {
//!     match coroutine.resume(&mut fragmentizer, arg.take()) {
//!         ImapCoroutineState::Yielded(ImapSessionOpenYield::WantsTcpConnect { host, port }) => {
//!             stream = Some(TcpStream::connect((host.as_str(), port)).unwrap());
//!         }
//!         ImapCoroutineState::Yielded(ImapSessionOpenYield::WantsWrite(bytes)) => {
//!             stream.as_mut().unwrap().write_all(&bytes).unwrap();
//!         }
//!         ImapCoroutineState::Yielded(ImapSessionOpenYield::WantsRead) => {
//!             let n = stream.as_mut().unwrap().read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         ImapCoroutineState::Yielded(yielded) => panic!("unexpected {yielded:?} over plain TCP"),
//!         ImapCoroutineState::Complete(Ok(session)) => break session,
//!         ImapCoroutineState::Complete(Err(err)) => panic!("{err}"),
//!     }
//! };
//!
//! println!("{:?}", session.capability);
//! ```

use core::fmt;

use alloc::{string::String, vec, vec::Vec};

use imap_codec::{
    fragmentizer::Fragmentizer,
    imap_types::{
        core::{IString, NString},
        error::ValidationError,
        response::Capability,
    },
};
use log::debug;
#[cfg(feature = "scram")]
use pimalaya_stream::sasl::SaslScramSha256;
use pimalaya_stream::sasl::{
    Sasl, SaslAnonymous, SaslLogin, SaslOauthbearer, SaslPlain, SaslXoauth2,
};
use secrecy::ExposeSecret;
use thiserror::Error;
#[cfg(feature = "url")]
use url::Url;

#[cfg(feature = "scram")]
use crate::rfc7677::auth_scram_sha_256::*;
use crate::{
    coroutine::*,
    imap_try,
    rfc3501::{capability::*, greeting::*, login::*, starttls::*},
    rfc7628::auth_oauthbearer::*,
    sasl::{auth_anonymous::*, auth_login::*, auth_plain::*, auth_xoauth2::*},
};

/// Failure causes while opening an IMAP session.
#[derive(Debug, Error)]
pub enum ImapSessionOpenError {
    /// STARTTLS was requested on a transport that is already TLS.
    #[error("STARTTLS requested on an already-encrypted transport: TLS is active")]
    StartTlsOverTls,
    /// The server sent bytes past the STARTTLS tagged response.
    ///
    /// RFC 3501 §6.2.1 forbids them, so their presence means an attacker
    /// injected plaintext commands the server will replay inside the TLS
    /// session. The upgrade is refused rather than performed.
    #[error("IMAP STARTTLS response carried trailing bytes: refusing the TLS upgrade")]
    StartTlsInjection,
    /// SCRAM-SHA-256 was requested but the scram feature is off.
    #[cfg(not(feature = "scram"))]
    #[error("SCRAM-SHA-256 SASL mechanism requires the `scram` cargo feature")]
    ScramSha256NotEnabled,
    /// The URL carries no host to connect to.
    #[cfg(feature = "url")]
    #[error("IMAP URL `{0}` has no host")]
    UrlMissingHost(String),
    /// The URL scheme is none of imap, imaps and unix.
    #[cfg(feature = "url")]
    #[error("IMAP URL `{0}` has unsupported scheme `{1}` (expected `imap`, `imaps` or `unix`)")]
    UrlUnsupportedScheme(String, String),
    /// The LOGIN user or password failed imap-types validation.
    #[error("Invalid IMAP LOGIN credentials")]
    InvalidLoginCredentials(#[from] ValidationError),
    /// The STARTTLS coroutine failed.
    #[error(transparent)]
    StartTls(#[from] ImapStartTlsError),
    /// The greeting coroutine failed.
    #[error(transparent)]
    Greeting(#[from] ImapGreetingGetError),
    /// The CAPABILITY coroutine failed.
    #[error(transparent)]
    Capability(#[from] ImapCapabilityGetError),
    /// The LOGIN coroutine failed.
    #[error(transparent)]
    Login(#[from] ImapLoginError),
    /// The SASL ANONYMOUS coroutine failed.
    #[error(transparent)]
    AuthAnonymous(#[from] ImapAuthAnonymousError),
    /// The SASL LOGIN coroutine failed.
    #[error(transparent)]
    AuthLogin(#[from] ImapAuthLoginError),
    /// The SASL PLAIN coroutine failed.
    #[error(transparent)]
    AuthPlain(#[from] ImapAuthPlainError),
    /// The SASL OAUTHBEARER coroutine failed.
    #[error(transparent)]
    AuthOauthbearer(#[from] ImapAuthOauthbearerError),
    /// The SASL XOAUTH2 coroutine failed.
    #[error(transparent)]
    AuthXoauth2(#[from] ImapAuthXoauth2Error),
    /// The SASL SCRAM-SHA-256 coroutine failed.
    #[cfg(feature = "scram")]
    #[error(transparent)]
    AuthScramSha256(#[from] ImapAuthScramSha256Error),
}

/// Where and how the connection is opened.
///
/// The scheme table that maps an IMAP URL onto one of these variants is
/// protocol knowledge, so it lives here rather than in the transport
/// layer; see [`ImapSessionTransport::from_url`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ImapSessionTransport {
    /// Plain TCP, the `imap://` scheme. Pair it with
    /// [`ImapSessionOpenOptions::starttls`] to reach a TLS session.
    Tcp {
        /// The server host name.
        host: String,
        /// The server port, conventionally 143.
        port: u16,
    },
    /// Implicit TLS, the `imaps://` scheme.
    Tls {
        /// The server host name.
        host: String,
        /// The server port, conventionally 993.
        port: u16,
    },
    /// A local unix domain socket, the `unix://` scheme, typically a
    /// pre-authenticated socket proxy answering with a PREAUTH greeting.
    Unix(String),
}

#[cfg(feature = "url")]
impl ImapSessionTransport {
    /// Reads the transport out of an IMAP URL.
    ///
    /// `imap://` is plain TCP on port 143, `imaps://` is implicit TLS on
    /// port 993 and `unix://` is a local socket path; an explicit port in
    /// the URL wins over the default.
    pub fn from_url(url: &Url) -> Result<Self, ImapSessionOpenError> {
        let scheme = url.scheme();

        if scheme.eq_ignore_ascii_case("unix") {
            return Ok(Self::Unix(String::from(url.path())));
        }

        let Some(host) = url.host_str() else {
            let url = String::from(url.as_str());
            return Err(ImapSessionOpenError::UrlMissingHost(url));
        };

        let host = String::from(host);
        let port = url.port().unwrap_or_else(|| default_port(scheme));

        if scheme.eq_ignore_ascii_case("imap") {
            Ok(Self::Tcp { host, port })
        } else if scheme.eq_ignore_ascii_case("imaps") {
            Ok(Self::Tls { host, port })
        } else {
            let scheme = String::from(scheme);
            let url = String::from(url.as_str());
            Err(ImapSessionOpenError::UrlUnsupportedScheme(url, scheme))
        }
    }
}

/// Provider-quirk and policy options for [`ImapSessionOpen::new`].
///
/// The default upgrades nothing, sends no `ID` and follows the server's
/// advertised capabilities.
#[derive(Clone, Debug, Default)]
pub struct ImapSessionOpenOptions {
    /// Whether to upgrade the connection with `STARTTLS` after the
    /// greeting. Only valid on a cleartext transport, since
    /// [`ImapSessionTransport::Tls`] is already encrypted.
    pub starttls: bool,
    /// ID parameters consumed by the authentication step, required by a
    /// few providers (mail.qq.com, Fastmail).
    ///
    /// `None` skips, `Some(empty)` sends `ID NIL`, `Some(params)` sends
    /// `ID (k v ...)`.
    pub auto_id: Option<Vec<(IString<'static>, NString<'static>)>>,
    /// Forces the RFC 4959 SASL-IR initial response on or off.
    ///
    /// `Some(true)` inlines it with the `AUTHENTICATE` command,
    /// `Some(false)` waits for the server's continuation request, and
    /// `None` follows the advertised `SASL-IR` capability. Coremail
    /// (126.com, 163.com) advertises it falsely, and no capability
    /// inspection can predict that.
    pub sasl_ir: Option<bool>,
}

/// An opened IMAP session.
#[derive(Clone, Debug)]
pub struct ImapSessionOpenData {
    /// The capabilities advertised once the session reached its final
    /// state, after authentication when one took place.
    pub capability: Vec<Capability<'static>>,
    /// Whether the greeting was `PREAUTH`: the session opened already
    /// authenticated, so the SASL step was skipped.
    pub pre_authenticated: bool,
}

/// Requests emitted while opening a session.
///
/// The three connect variants and the upgrade are what set this
/// coroutine apart from a command coroutine: the caller answers them
/// with its own sockets, whatever the runtime.
#[derive(Debug)]
pub enum ImapSessionOpenYield {
    /// The caller opens a plain TCP connection and resumes.
    WantsTcpConnect {
        /// The server host name.
        host: String,
        /// The server port.
        port: u16,
    },
    /// The caller opens a TLS connection and resumes.
    WantsTlsConnect {
        /// The server host name, also the certificate name to verify.
        host: String,
        /// The server port.
        port: u16,
    },
    /// The caller connects to the unix socket at this path and resumes.
    WantsUnixConnect(String),
    /// The caller upgrades the open connection to TLS and resumes.
    ///
    /// Emitted only once the STARTTLS exchange completed cleanly; the
    /// coroutine refuses the upgrade itself when the server appended
    /// bytes to its tagged response.
    WantsTlsUpgrade,
    /// The caller reads from its stream and resumes with the bytes.
    WantsRead,
    /// The caller writes the given bytes to its stream and resumes.
    WantsWrite(Vec<u8>),
}

impl From<ImapYield> for ImapSessionOpenYield {
    fn from(y: ImapYield) -> Self {
        match y {
            ImapYield::WantsRead => Self::WantsRead,
            ImapYield::WantsWrite(bytes) => Self::WantsWrite(bytes),
        }
    }
}

/// I/O-free IMAP session-opening coroutine.
pub struct ImapSessionOpen {
    state: State,
    transport: ImapSessionTransport,
    sasl: Option<Sasl>,
    capability: Vec<Capability<'static>>,
    pre_authenticated: bool,
    opts: ImapSessionOpenOptions,
}

impl ImapSessionOpen {
    /// Builds a session-opening coroutine reaching `transport` and
    /// authenticating with `sasl`.
    ///
    /// `sasl` of `None` stops after the greeting, which is what a
    /// pre-authenticated socket proxy wants; a `Some` mechanism is
    /// skipped anyway when the greeting turns out to be PREAUTH.
    pub fn new(
        transport: ImapSessionTransport,
        sasl: Option<impl Into<Sasl>>,
        opts: ImapSessionOpenOptions,
    ) -> Self {
        Self {
            state: State::Connect,
            transport,
            sasl: sasl.map(Into::into),
            capability: Vec::new(),
            pre_authenticated: false,
            opts,
        }
    }

    /// Picks the SASL mechanism, resolves the SASL-IR policy and hands
    /// the observed capabilities to the auth coroutine.
    ///
    /// Returns `None` when there is nothing to authenticate: no
    /// mechanism was given, or the greeting was PREAUTH.
    fn wants_auth(&mut self) -> Result<Option<State>, ImapSessionOpenError> {
        if self.pre_authenticated {
            return Ok(None);
        }

        let Some(sasl) = self.sasl.take() else {
            return Ok(None);
        };

        let initial_request = self
            .opts
            .sasl_ir
            .unwrap_or_else(|| self.capability.contains(&Capability::SaslIr));
        let auto_id = self.opts.auto_id.take();
        let ensure_capabilities = true;

        let auth = match sasl {
            Sasl::Anonymous(SaslAnonymous { message }) => {
                let opts = ImapAuthAnonymousOptions {
                    initial_request,
                    ensure_capabilities,
                    auto_id,
                };

                Auth::Anonymous(ImapAuthAnonymous::new(message, opts))
            }
            Sasl::Login(SaslLogin { username, password }) => {
                let opts = ImapLoginOptions {
                    ensure_capabilities,
                    auto_id,
                };

                Auth::Login(ImapLogin::new(username, password.expose_secret(), opts)?)
            }
            Sasl::Plain(SaslPlain {
                authzid,
                authcid,
                passwd,
            }) => {
                let opts = ImapAuthPlainOptions {
                    initial_request,
                    ensure_capabilities,
                    auto_id,
                };

                Auth::Plain(ImapAuthPlain::new(
                    authzid,
                    authcid,
                    passwd.expose_secret(),
                    opts,
                ))
            }
            Sasl::Oauthbearer(SaslOauthbearer {
                username,
                host,
                port,
                token,
            }) => {
                let opts = ImapAuthOauthbearerOptions {
                    initial_request,
                    ensure_capabilities,
                    auto_id,
                };

                Auth::Oauthbearer(ImapAuthOauthbearer::new(
                    username,
                    host,
                    port,
                    token.expose_secret(),
                    opts,
                ))
            }
            Sasl::Xoauth2(SaslXoauth2 { username, token }) => {
                let opts = ImapAuthXoauth2Options {
                    initial_request,
                    ensure_capabilities,
                    auto_id,
                };

                Auth::Xoauth2(ImapAuthXoauth2::new(username, token.expose_secret(), opts))
            }
            #[cfg(feature = "scram")]
            Sasl::ScramSha256(SaslScramSha256 { username, password }) => {
                let opts = ImapAuthScramSha256Options {
                    initial_request,
                    ensure_capabilities,
                    auto_id,
                };

                Auth::ScramSha256(ImapAuthScramSha256::new(
                    username,
                    password.expose_secret(),
                    opts,
                ))
            }
            #[cfg(not(feature = "scram"))]
            Sasl::ScramSha256(_) => {
                return Err(ImapSessionOpenError::ScramSha256NotEnabled);
            }
        };

        Ok(Some(State::Auth(auth)))
    }

    /// Terminal value, taking the capabilities observed along the way.
    fn complete(
        &mut self,
    ) -> ImapCoroutineState<ImapSessionOpenYield, <Self as ImapCoroutine>::Return> {
        let data = ImapSessionOpenData {
            capability: core::mem::take(&mut self.capability),
            pre_authenticated: self.pre_authenticated,
        };

        ImapCoroutineState::Complete(Ok(data))
    }
}

impl ImapCoroutine for ImapSessionOpen {
    type Yield = ImapSessionOpenYield;
    type Return = Result<ImapSessionOpenData, ImapSessionOpenError>;

    fn resume(
        &mut self,
        fragmentizer: &mut Fragmentizer,
        arg: Option<&[u8]>,
    ) -> ImapCoroutineState<Self::Yield, Self::Return> {
        loop {
            match &mut self.state {
                State::Connect => {
                    let is_tls = matches!(self.transport, ImapSessionTransport::Tls { .. });

                    if self.opts.starttls && is_tls {
                        let err = ImapSessionOpenError::StartTlsOverTls;
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    // NOTE: the transport is small and read once per
                    // session, so cloning it out beats threading an
                    // Option through the whole state machine.
                    let yielded = match &self.transport {
                        ImapSessionTransport::Tcp { host, port } => {
                            ImapSessionOpenYield::WantsTcpConnect {
                                host: host.clone(),
                                port: *port,
                            }
                        }
                        ImapSessionTransport::Tls { host, port } => {
                            ImapSessionOpenYield::WantsTlsConnect {
                                host: host.clone(),
                                port: *port,
                            }
                        }
                        ImapSessionTransport::Unix(path) => {
                            ImapSessionOpenYield::WantsUnixConnect(path.clone())
                        }
                    };

                    self.state = State::Connected;
                    debug!("{}", self.state);

                    return ImapCoroutineState::Yielded(yielded);
                }
                State::Connected => {
                    self.state = if self.opts.starttls {
                        State::StartTls(ImapStartTls::new())
                    } else {
                        State::Greeting(ImapGreetingGet::new(ImapGreetingGetOptions {
                            ensure_capabilities: true,
                        }))
                    };

                    debug!("{}", self.state);
                }
                State::StartTls(starttls) => {
                    let leftover = imap_try!(starttls, fragmentizer, arg);

                    if !leftover.is_empty() {
                        let err = ImapSessionOpenError::StartTlsInjection;
                        return ImapCoroutineState::Complete(Err(err));
                    }

                    self.state = State::Upgraded;
                    debug!("{}", self.state);

                    return ImapCoroutineState::Yielded(ImapSessionOpenYield::WantsTlsUpgrade);
                }
                State::Upgraded => {
                    // NOTE: RFC 3501 §6.2.1 invalidates the pre-upgrade
                    // capability list, so it is re-read over TLS rather
                    // than carried across. A STARTTLS session never
                    // reaches PREAUTH: the greeting was consumed by the
                    // STARTTLS coroutine before the upgrade.
                    self.state = State::Capability(ImapCapabilityGet::new());
                    debug!("{}", self.state);
                }
                State::Capability(capability) => {
                    self.capability = imap_try!(capability, fragmentizer, arg);

                    match self.wants_auth() {
                        Err(err) => return ImapCoroutineState::Complete(Err(err)),
                        Ok(None) => return self.complete(),
                        Ok(Some(next)) => {
                            self.state = next;
                            debug!("{}", self.state);
                        }
                    }
                }
                State::Greeting(greeting) => {
                    let greeting = imap_try!(greeting, fragmentizer, arg);

                    self.capability = greeting.capability;
                    self.pre_authenticated = greeting.pre_authenticated;

                    match self.wants_auth() {
                        Err(err) => return ImapCoroutineState::Complete(Err(err)),
                        Ok(None) => return self.complete(),
                        Ok(Some(next)) => {
                            self.state = next;
                            debug!("{}", self.state);
                        }
                    }
                }
                State::Auth(auth) => {
                    self.capability = match auth {
                        Auth::Anonymous(auth) => imap_try!(auth, fragmentizer, arg),
                        Auth::Login(auth) => imap_try!(auth, fragmentizer, arg),
                        Auth::Plain(auth) => imap_try!(auth, fragmentizer, arg),
                        Auth::Oauthbearer(auth) => imap_try!(auth, fragmentizer, arg),
                        Auth::Xoauth2(auth) => imap_try!(auth, fragmentizer, arg),
                        #[cfg(feature = "scram")]
                        Auth::ScramSha256(auth) => imap_try!(auth, fragmentizer, arg),
                    };

                    return self.complete();
                }
            }
        }
    }
}

/// Default ALPN identifier for IMAP TLS ([RFC 7595]).
///
/// [RFC 7595]: https://www.rfc-editor.org/rfc/rfc7595
pub fn default_alpn() -> Vec<String> {
    vec![String::from("imap")]
}

/// Default IMAP port for `scheme`: 993 for `imaps`, 143 otherwise.
pub fn default_port(scheme: &str) -> u16 {
    if scheme.eq_ignore_ascii_case("imaps") {
        993
    } else {
        143
    }
}

// NOTE: the variants differ by some 700 bytes, since every coroutine
// sending a command carries an ImapSend of its own, and the lint would
// have each state boxed. One allocation per transition buys less than
// the copy it saves: a session moves through four of these.
#[allow(clippy::large_enum_variant)]
enum State {
    Connect,
    Connected,
    StartTls(ImapStartTls),
    Upgraded,
    Capability(ImapCapabilityGet),
    Greeting(ImapGreetingGet),
    Auth(Auth),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect => f.write_str("open connection"),
            Self::Connected => f.write_str("connection opened"),
            Self::StartTls(_) => f.write_str("send starttls"),
            Self::Upgraded => f.write_str("connection upgraded to tls"),
            Self::Capability(_) => f.write_str("fetch capabilities"),
            Self::Greeting(_) => f.write_str("read greeting"),
            Self::Auth(auth) => write!(f, "authenticate with {auth}"),
        }
    }
}

enum Auth {
    Anonymous(ImapAuthAnonymous),
    Login(ImapLogin),
    Plain(ImapAuthPlain),
    Oauthbearer(ImapAuthOauthbearer),
    Xoauth2(ImapAuthXoauth2),
    #[cfg(feature = "scram")]
    ScramSha256(ImapAuthScramSha256),
}

impl fmt::Display for Auth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Anonymous(_) => f.write_str("anonymous"),
            Self::Login(_) => f.write_str("login"),
            Self::Plain(_) => f.write_str("plain"),
            Self::Oauthbearer(_) => f.write_str("oauthbearer"),
            Self::Xoauth2(_) => f.write_str("xoauth2"),
            #[cfg(feature = "scram")]
            Self::ScramSha256(_) => f.write_str("scram-sha-256"),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use crate::session::*;

    #[test]
    fn tcp_transport_yields_tcp_connect_then_greeting() {
        let transport = ImapSessionTransport::Tcp {
            host: "localhost".to_string(),
            port: 143,
        };

        let mut session = ImapSessionOpen::new(transport, None::<Sasl>, Default::default());
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        match session.resume(&mut frag, None) {
            ImapCoroutineState::Yielded(ImapSessionOpenYield::WantsTcpConnect { host, port }) => {
                assert_eq!(host, "localhost");
                assert_eq!(port, 143);
            }
            state => panic!("expected WantsTcpConnect, got {state:?}"),
        }

        match session.resume(&mut frag, None) {
            ImapCoroutineState::Yielded(ImapSessionOpenYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }

        let greeting = b"* OK [CAPABILITY IMAP4REV1] server ready\r\n";
        match session.resume(&mut frag, Some(greeting)) {
            ImapCoroutineState::Complete(Ok(data)) => {
                assert!(!data.pre_authenticated);
                assert_eq!(data.capability, vec![Capability::Imap4Rev1]);
            }
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    #[test]
    fn preauth_greeting_skips_the_sasl_step() {
        let transport = ImapSessionTransport::Unix("/run/sirup.sock".to_string());
        let sasl = SaslPlain {
            authzid: None,
            authcid: "alice".to_string(),
            passwd: "secret".to_string().into(),
        };

        let mut session = ImapSessionOpen::new(transport, Some(sasl), Default::default());
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        match session.resume(&mut frag, None) {
            ImapCoroutineState::Yielded(ImapSessionOpenYield::WantsUnixConnect(path)) => {
                assert_eq!(path, "/run/sirup.sock");
            }
            state => panic!("expected WantsUnixConnect, got {state:?}"),
        }

        match session.resume(&mut frag, None) {
            ImapCoroutineState::Yielded(ImapSessionOpenYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }

        let greeting = b"* PREAUTH [CAPABILITY IMAP4REV1] already authenticated\r\n";
        match session.resume(&mut frag, Some(greeting)) {
            ImapCoroutineState::Complete(Ok(data)) => assert!(data.pre_authenticated),
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    #[test]
    fn starttls_over_tls_fails_before_opening_a_socket() {
        let transport = ImapSessionTransport::Tls {
            host: "localhost".to_string(),
            port: 993,
        };

        let opts = ImapSessionOpenOptions {
            starttls: true,
            ..Default::default()
        };

        let mut session = ImapSessionOpen::new(transport, None::<Sasl>, opts);
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        match session.resume(&mut frag, None) {
            ImapCoroutineState::Complete(Err(ImapSessionOpenError::StartTlsOverTls)) => {}
            state => panic!("expected StartTlsOverTls, got {state:?}"),
        }
    }

    #[test]
    fn starttls_reaches_the_upgrade_then_refetches_capabilities() {
        let transport = ImapSessionTransport::Tcp {
            host: "localhost".to_string(),
            port: 143,
        };

        let opts = ImapSessionOpenOptions {
            starttls: true,
            ..Default::default()
        };

        let mut session = ImapSessionOpen::new(transport, None::<Sasl>, opts);
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        assert!(matches!(
            session.resume(&mut frag, None),
            ImapCoroutineState::Yielded(ImapSessionOpenYield::WantsTcpConnect { .. })
        ));
        assert!(matches!(
            session.resume(&mut frag, None),
            ImapCoroutineState::Yielded(ImapSessionOpenYield::WantsRead)
        ));

        // NOTE: the STARTTLS coroutine discards the plaintext greeting
        // line before issuing its own command.
        let greeting = b"* OK server ready\r\n";
        let command = match session.resume(&mut frag, Some(greeting)) {
            ImapCoroutineState::Yielded(ImapSessionOpenYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        };

        let command = String::from_utf8(command).expect("utf8 command");
        assert!(command.contains("STARTTLS"));
        let tag = command
            .split_whitespace()
            .next()
            .expect("first whitespace-separated token")
            .to_string();

        assert!(matches!(
            session.resume(&mut frag, None),
            ImapCoroutineState::Yielded(ImapSessionOpenYield::WantsRead)
        ));

        let reply = alloc::format!("{tag} OK begin TLS negotiation\r\n");
        assert!(matches!(
            session.resume(&mut frag, Some(reply.as_bytes())),
            ImapCoroutineState::Yielded(ImapSessionOpenYield::WantsTlsUpgrade)
        ));

        // NOTE: the caller has swapped in the TLS stream; the coroutine
        // must now re-issue CAPABILITY rather than trust the pre-upgrade
        // list.
        let command = match session.resume(&mut frag, None) {
            ImapCoroutineState::Yielded(ImapSessionOpenYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        };

        let command = String::from_utf8(command).expect("utf8 command");
        assert!(command.contains("CAPABILITY"));
    }

    #[test]
    fn starttls_trailing_bytes_refuse_the_upgrade() {
        let transport = ImapSessionTransport::Tcp {
            host: "localhost".to_string(),
            port: 143,
        };

        let opts = ImapSessionOpenOptions {
            starttls: true,
            ..Default::default()
        };

        let mut session = ImapSessionOpen::new(transport, None::<Sasl>, opts);
        let mut frag = Fragmentizer::new(50 * 1024 * 1024);

        session.resume(&mut frag, None);
        session.resume(&mut frag, None);

        let command = match session.resume(&mut frag, Some(b"* OK server ready\r\n")) {
            ImapCoroutineState::Yielded(ImapSessionOpenYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        };

        let command = String::from_utf8(command).expect("utf8 command");
        let tag = command
            .split_whitespace()
            .next()
            .expect("first whitespace-separated token")
            .to_string();

        session.resume(&mut frag, None);

        // NOTE: the injected NOOP rides in the same TCP segment as the
        // tagged OK, so the server would replay it inside the TLS
        // session.
        let reply = alloc::format!("{tag} OK begin TLS negotiation\r\na1 NOOP\r\n");
        match session.resume(&mut frag, Some(reply.as_bytes())) {
            ImapCoroutineState::Complete(Err(ImapSessionOpenError::StartTlsInjection)) => {}
            state => panic!("expected StartTlsInjection, got {state:?}"),
        }
    }

    #[cfg(feature = "url")]
    #[test]
    fn urls_map_onto_transports() {
        let url = Url::parse("imap://example.org").unwrap();
        let expected = ImapSessionTransport::Tcp {
            host: "example.org".to_string(),
            port: 143,
        };
        assert_eq!(ImapSessionTransport::from_url(&url).unwrap(), expected);

        let url = Url::parse("imaps://example.org:1993").unwrap();
        let expected = ImapSessionTransport::Tls {
            host: "example.org".to_string(),
            port: 1993,
        };
        assert_eq!(ImapSessionTransport::from_url(&url).unwrap(), expected);

        let url = Url::parse("unix:///run/sirup.sock").unwrap();
        let expected = ImapSessionTransport::Unix("/run/sirup.sock".to_string());
        assert_eq!(ImapSessionTransport::from_url(&url).unwrap(), expected);

        let url = Url::parse("http://example.org").unwrap();
        let err = ImapSessionTransport::from_url(&url).unwrap_err();
        assert!(matches!(
            err,
            ImapSessionOpenError::UrlUnsupportedScheme(_, _)
        ));
    }
}
