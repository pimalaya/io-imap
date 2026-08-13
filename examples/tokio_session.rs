//! Full tokio session: answer every [`ImapSessionOpen`] transport
//! request with tokio sockets and tokio-rustls, then implement
//! [`ImapClientAsync`] over the same socket so the forty-odd commands
//! come with it.
//!
//! This is the "any other runtime" case. No io-imap TLS feature is
//! involved: the runtime, the sockets and the TLS stack belong to the
//! consumer. What stays in io-imap is the protocol thinking, and the
//! coroutine hands it over as a checklist: which socket the URL scheme
//! implies, that the greeting precedes STARTTLS, that CAPABILITY is
//! re-issued after the upgrade, that a PREAUTH greeting skips
//! authentication, and whether the RFC 4959 initial response may ride
//! along. The loop below answers requests, it decides nothing.
//!
//! Run with: `URL=imaps://imap.example.org LOGIN=alice PASSWORD=secret cargo run --example tokio_session`
//!
//! `imap://` opens plain TCP, `imaps://` implicit TLS and `unix://` a
//! local socket. Setting `STARTTLS=1` on an `imap://` URL takes the
//! upgrade path. Omitting the credentials stops after the greeting,
//! which is what a pre-authenticated socket proxy wants.

use std::{env, error::Error, io, sync::Arc};

use io_imap::{
    client::{ImapClientAsync, ImapClientError},
    codec::fragmentizer::Fragmentizer,
    coroutine::*,
    session::*,
    types::{
        mailbox::{ListMailbox, Mailbox},
        response::Capability,
    },
};
use pimalaya_stream::sasl::{Sasl, SaslPlain};
use rustls::{ClientConfig, pki_types::ServerName};
use rustls_platform_verifier::ConfigVerifierExt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UnixStream},
};
use tokio_rustls::{TlsConnector, client::TlsStream};
use url::Url;

/// Biggest server message the parser accepts, as in the std client.
const FRAGMENTIZER_MAX_MESSAGE_SIZE: u32 = 100 * 1024 * 1024;

/// Read buffer, sized for line-oriented protocol traffic.
const READ_BUFFER_SIZE: usize = 16 * 1024;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let url = Url::parse(&env::var("URL")?)?;
    let starttls = env::var("STARTTLS").is_ok();

    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let config = ClientConfig::with_platform_verifier()?;
    let connector = TlsConnector::from(Arc::new(config));

    let sasl = env::var("LOGIN")
        .ok()
        .zip(env::var("PASSWORD").ok())
        .map(|(authcid, passwd)| SaslPlain {
            authzid: None,
            authcid,
            passwd: passwd.into(),
        });

    let opts = ImapSessionOpenOptions {
        starttls,
        ..Default::default()
    };

    let (mut client, capability) = ImapClientTokio::connect(&url, &connector, sasl, opts).await?;

    for capability in &capability {
        println!("{capability:?}");
    }

    let reference = Mailbox::try_from(String::new())?;
    let pattern = ListMailbox::try_from("*")?;

    // NOTE: `list` is one of the trait's default bodies, and the future
    // it returns is Send, so a command can move onto another task. That
    // is why `run` is declared as `impl Future<..> + Send` rather than
    // written as an `async fn`: an `async fn` in a trait cannot promise
    // Send, and this spawn would stop compiling.
    let listing = tokio::spawn(async move { client.list(reference, pattern).await }).await??;

    for (mailbox, _delimiter, _attributes) in listing {
        println!("{mailbox:?}");
    }

    Ok(())
}

/// A tokio IMAP client: a socket, the connection-wide parser buffer,
/// and nothing else. Every command comes from [`ImapClientAsync`].
struct ImapClientTokio {
    stream: TokioStream,
    fragmentizer: Fragmentizer,
}

impl ImapClientTokio {
    /// Opens an authenticated session at `url` by answering the
    /// coroutine's transport requests with tokio sockets.
    ///
    /// The four transport requests are the whole difference between
    /// this and a command pump: connect a TCP socket, connect a TLS
    /// one, connect a unix socket, upgrade the open one. Ordering is
    /// the coroutine's business, so a caller that gets it wrong is
    /// never asked for the next step.
    async fn connect(
        url: &Url,
        connector: &TlsConnector,
        sasl: Option<impl Into<Sasl>>,
        opts: ImapSessionOpenOptions,
    ) -> Result<(Self, Vec<Capability<'static>>), Box<dyn Error>> {
        let transport = ImapSessionTransport::from_url(url)?;
        let mut session = ImapSessionOpen::new(transport, sasl, opts);
        let mut fragmentizer = Fragmentizer::new(FRAGMENTIZER_MAX_MESSAGE_SIZE);
        let mut stream: Option<TokioStream> = None;
        let mut buf = [0u8; READ_BUFFER_SIZE];
        let mut arg: Option<&[u8]> = None;

        // NOTE: WantsTlsUpgrade carries no payload, so the host name of
        // the plaintext connect is kept for the certificate check the
        // upgrade performs later.
        let mut tls_host = String::new();

        // NOTE: the state machine always asks for a connect before any
        // read, write or upgrade, so the socket is open by the time
        // those arrive.
        let missing = || String::from("IMAP session yielded I/O before connecting");

        loop {
            match session.resume(&mut fragmentizer, arg.take()) {
                ImapCoroutineState::Complete(Err(err)) => return Err(err.into()),
                ImapCoroutineState::Complete(Ok(data)) => {
                    let client = Self {
                        stream: stream.ok_or_else(missing)?,
                        fragmentizer,
                    };

                    return Ok((client, data.capability));
                }
                ImapCoroutineState::Yielded(ImapSessionOpenYield::WantsTcpConnect {
                    host,
                    port,
                }) => {
                    let sock = TcpStream::connect((host.as_str(), port)).await?;

                    tls_host = host;
                    stream = Some(TokioStream::Tcp(sock));
                }
                ImapCoroutineState::Yielded(ImapSessionOpenYield::WantsTlsConnect {
                    host,
                    port,
                }) => {
                    let name = ServerName::try_from(host.as_str())?.to_owned();
                    let sock = TcpStream::connect((host.as_str(), port)).await?;

                    stream = Some(TokioStream::Tls(Box::new(
                        connector.connect(name, sock).await?,
                    )));
                }
                ImapCoroutineState::Yielded(ImapSessionOpenYield::WantsUnixConnect(path)) => {
                    let sock = UnixStream::connect(path).await?;

                    stream = Some(TokioStream::Unix(sock));
                }
                ImapCoroutineState::Yielded(ImapSessionOpenYield::WantsTlsUpgrade) => {
                    // NOTE: the STARTTLS exchange already happened and
                    // came back clean; the coroutine refuses the upgrade
                    // itself when the server appended bytes to its
                    // tagged response, so injected commands cannot ride
                    // into the TLS session.
                    let plain = stream.take().ok_or_else(missing)?;

                    stream = Some(plain.upgrade_tls(connector, &tls_host).await?);
                }
                ImapCoroutineState::Yielded(ImapSessionOpenYield::WantsRead) => {
                    let n = stream.as_mut().ok_or_else(missing)?.read(&mut buf).await?;

                    arg = Some(&buf[..n]);
                }
                ImapCoroutineState::Yielded(ImapSessionOpenYield::WantsWrite(bytes)) => {
                    stream
                        .as_mut()
                        .ok_or_else(missing)?
                        .write_all(&bytes)
                        .await?;
                }
            }
        }
    }
}

impl ImapClientAsync for ImapClientTokio {
    // NOTE: clippy asks to collapse this into an `async fn`. Refuse: an
    // `async fn` in a trait cannot state that its future is Send, and
    // that Send bound is what lets any command built on this method
    // move onto a spawned task.
    #[allow(clippy::manual_async_fn)]
    fn run<C, T, E>(
        &mut self,
        mut coroutine: C,
    ) -> impl Future<Output = Result<T, ImapClientError>> + Send
    where
        C: ImapCoroutine<Yield = ImapYield, Return = Result<T, E>> + Send,
        T: Send,
        E: Send,
        ImapClientError: From<E>,
    {
        async move {
            let mut buf = [0u8; READ_BUFFER_SIZE];
            let mut arg: Option<&[u8]> = None;

            loop {
                match coroutine.resume(&mut self.fragmentizer, arg.take()) {
                    ImapCoroutineState::Complete(Ok(out)) => return Ok(out),
                    ImapCoroutineState::Complete(Err(err)) => return Err(err.into()),
                    ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
                        let n = self.stream.read(&mut buf).await?;

                        if n == 0 {
                            let kind = io::ErrorKind::UnexpectedEof;
                            let err = io::Error::new(kind, "IMAP server closed the connection");

                            return Err(err.into());
                        }

                        arg = Some(&buf[..n]);
                    }
                    ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
                        self.stream.write_all(&bytes).await?;
                    }
                }
            }
        }
    }
}

/// The sockets [`ImapSessionOpen`] can ask for, plus the TLS session a
/// STARTTLS upgrade swaps in.
enum TokioStream {
    /// Plain TCP, from an `imap://` URL.
    Tcp(TcpStream),
    /// TLS, either from an `imaps://` URL or from a STARTTLS upgrade.
    ///
    /// Boxed because a rustls session is far bigger than a bare socket,
    /// and an enum is as wide as its widest variant.
    Tls(Box<TlsStream<TcpStream>>),
    /// A local unix socket, from a `unix://` URL.
    Unix(UnixStream),
}

impl TokioStream {
    /// Reads whatever the socket has, as the coroutine feeds partial
    /// reads back through the fragmentizer.
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.read(buf).await,
            Self::Tls(stream) => stream.read(buf).await,
            Self::Unix(stream) => stream.read(buf).await,
        }
    }

    /// Writes a whole command; a short write would desynchronise the
    /// exchange.
    async fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.write_all(bytes).await,
            Self::Tls(stream) => stream.write_all(bytes).await,
            Self::Unix(stream) => stream.write_all(bytes).await,
        }
    }

    /// Consumes the plaintext socket and hands it to rustls, the
    /// STARTTLS half the coroutine cannot perform itself.
    async fn upgrade_tls(
        self,
        connector: &TlsConnector,
        host: &str,
    ) -> Result<Self, Box<dyn Error>> {
        let Self::Tcp(sock) = self else {
            let err = String::from("IMAP STARTTLS upgrade on an already-encrypted transport");
            return Err(err.into());
        };

        let name = ServerName::try_from(host)?.to_owned();
        let tls = connector.connect(name, sock).await?;

        Ok(Self::Tls(Box::new(tls)))
    }
}
