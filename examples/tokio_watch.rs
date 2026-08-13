//! Tokio driver for the mailbox watch coroutine, cancelled by a
//! [`tokio::select!`] race instead of a read timeout.
//!
//! [`ImapMailboxWatch`] declares a yield vocabulary of its own, so it is
//! one of the coroutines the client traits deliberately leave out: how
//! events reach the application and how the loop winds down are the
//! consumer's decisions, not the crate's. This file makes one set of
//! them.
//!
//! Contrast with `ImapClientStd::watch_mailbox`. A blocking read cannot
//! be cancelled, so the std client moves the pump onto a thread, gives
//! the socket a five-second read timeout and treats every timeout
//! wakeup as a chance to poll the shutdown flag: shutdown is noticed up
//! to five seconds late, and the events come back over a bounded
//! channel. Here `AsyncReadExt::read` is cancel-safe, so the read and
//! the shutdown signal simply race in a select!. No thread, no timeout,
//! no polling, and the signal is observed the moment it is sent.
//!
//! The signal is a [`tokio::sync::watch`] channel because tokio-util is
//! not a dev-dependency of io-imap; a `CancellationToken` drops in
//! unchanged, and so does any other awaitable an application already
//! has.
//!
//! Run with: `HOST=imap.example.org LOGIN=alice PASSWORD=secret cargo run --example tokio_watch`
//!
//! Ctrl-C winds the watcher down.
//!
//! NOTE: the 29-second IDLE refresh that keeps middle-boxes from
//! dropping the connection is measured with a std `Instant`, so it is
//! compiled in with the `client` cargo feature (on by default). Built
//! without it, the IDLE below is never refreshed.

use core::sync::atomic::{AtomicBool, Ordering};
use std::{env, error::Error, sync::Arc};

use io_imap::{
    codec::fragmentizer::Fragmentizer,
    coroutine::*,
    session::*,
    types::{mailbox::Mailbox, response::Capability},
    watch::*,
};
use io_sasl::{mechanism::Sasl, rfc4616::plain::SaslPlainCreds};
use rustls::{ClientConfig, pki_types::ServerName};
use rustls_platform_verifier::ConfigVerifierExt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    select, signal,
    sync::watch,
};
use tokio_rustls::{TlsConnector, client::TlsStream};

/// Biggest server message the parser accepts, as in the std client.
const FRAGMENTIZER_MAX_MESSAGE_SIZE: u32 = 100 * 1024 * 1024;

/// Read buffer, sized for line-oriented protocol traffic.
const READ_BUFFER_SIZE: usize = 16 * 1024;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let host = env::var("HOST")?;
    let port: u16 = env::var("PORT")
        .ok()
        .and_then(|port| port.parse().ok())
        .unwrap_or(993);
    let mailbox = env::var("MAILBOX").unwrap_or_else(|_| String::from("INBOX"));

    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let sasl = SaslPlainCreds {
        authzid: None,
        authcid: env::var("LOGIN")?,
        passwd: env::var("PASSWORD")?.into(),
    };

    let session = TokioSession::open(&host, port, Some(sasl)).await?;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // NOTE: Ctrl-C stands in for whatever shutdown signal the
    // application has; the watch loop only ever sees the receiver.
    tokio::spawn(async move {
        signal::ctrl_c().await.ok();
        shutdown_tx.send(true).ok();
    });

    session
        .watch(Mailbox::try_from(mailbox)?, shutdown_rx)
        .await?;

    println!("watcher wound down");

    Ok(())
}

/// The session the watcher runs on: a dedicated TLS socket plus the
/// connection-wide parser buffer, and the capabilities the handshake
/// observed.
struct TokioSession {
    stream: TlsStream<TcpStream>,
    fragmentizer: Fragmentizer,
    capability: Vec<Capability<'static>>,
}

impl TokioSession {
    /// Opens an implicit-TLS session, the `imaps://` case.
    ///
    /// Only the TLS transport request is answered here, to keep the
    /// file about the watch loop; tokio_session.rs answers all four,
    /// STARTTLS upgrade included, and implements the client trait on
    /// top.
    async fn open(
        host: &str,
        port: u16,
        sasl: Option<impl Into<Sasl>>,
    ) -> Result<Self, Box<dyn Error>> {
        let config = ClientConfig::with_platform_verifier()?;
        let connector = TlsConnector::from(Arc::new(config));

        let transport = ImapSessionTransport::Tls {
            host: String::from(host),
            port,
        };

        let opts = ImapSessionOpenOptions::default();
        let mut session = ImapSessionOpen::new(transport, sasl, opts);
        let mut fragmentizer = Fragmentizer::new(FRAGMENTIZER_MAX_MESSAGE_SIZE);
        let mut stream: Option<TlsStream<TcpStream>> = None;
        let mut buf = [0u8; READ_BUFFER_SIZE];
        let mut arg: Option<&[u8]> = None;

        // NOTE: the state machine asks for the connect before any read
        // or write, so the socket is open by the time those arrive.
        let capability = loop {
            match session.resume(&mut fragmentizer, arg.take()) {
                ImapCoroutineState::Complete(Ok(data)) => break data.capability,
                ImapCoroutineState::Complete(Err(err)) => return Err(err.into()),
                ImapCoroutineState::Yielded(ImapSessionOpenYield::WantsTlsConnect {
                    host,
                    port,
                }) => {
                    let name = ServerName::try_from(host.as_str())?.to_owned();
                    let sock = TcpStream::connect((host.as_str(), port)).await?;

                    stream = Some(connector.connect(name, sock).await?);
                }
                ImapCoroutineState::Yielded(ImapSessionOpenYield::WantsRead) => {
                    let stream = stream.as_mut().expect("session connects before it reads");
                    let n = stream.read(&mut buf).await?;

                    arg = Some(&buf[..n]);
                }
                ImapCoroutineState::Yielded(ImapSessionOpenYield::WantsWrite(bytes)) => {
                    let stream = stream.as_mut().expect("session connects before it writes");

                    stream.write_all(&bytes).await?;
                }
                ImapCoroutineState::Yielded(yielded) => {
                    return Err(format!("unexpected {yielded:?} over implicit TLS").into());
                }
            }
        };

        Ok(Self {
            stream: stream.expect("session connects before it completes"),
            fragmentizer,
            capability,
        })
    }

    /// Watches `mailbox` until `shutdown` flips, printing every UID-keyed
    /// change the server reports.
    ///
    /// Takes the session by value: the watcher holds the connection in
    /// IDLE, so nothing else may use it until the loop returns.
    async fn watch(
        mut self,
        mailbox: Mailbox<'static>,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), Box<dyn Error>> {
        // NOTE: the coroutine reads this flag at the top of every
        // resume, so raising it does not abort the loop: it makes the
        // watcher leave IDLE with a DONE and return once the server has
        // acknowledged, which is what leaves the connection reusable.
        let flag = Arc::new(AtomicBool::new(false));
        let mut watcher = ImapMailboxWatch::new(&self.capability, mailbox, flag.clone())?;
        let mut buf = [0u8; READ_BUFFER_SIZE];
        let mut arg: Option<Vec<u8>> = None;

        loop {
            match watcher.resume(&mut self.fragmentizer, arg.as_deref()) {
                ImapCoroutineState::Complete(Ok(())) => return Ok(()),
                ImapCoroutineState::Complete(Err(err)) => return Err(err.into()),
                ImapCoroutineState::Yielded(ImapMailboxWatchYield::Event(event)) => {
                    println!("{event:?}");
                    arg = None;
                }
                ImapCoroutineState::Yielded(ImapMailboxWatchYield::WantsWrite(bytes)) => {
                    self.stream.write_all(&bytes).await?;
                    arg = None;
                }
                ImapCoroutineState::Yielded(ImapMailboxWatchYield::WantsRead) => {
                    // NOTE: the read and the shutdown signal race here.
                    // Losing the race costs nothing, because
                    // AsyncReadExt::read is cancel-safe: no bytes are
                    // consumed, and the next resume asks for the read
                    // again.
                    let n = select! {
                        read = self.stream.read(&mut buf) => read?,
                        _ = shutdown.changed() => {
                            flag.store(true, Ordering::SeqCst);
                            arg = None;
                            continue;
                        }
                    };

                    arg = Some(buf[..n].to_vec());
                }
            }
        }
    }
}
