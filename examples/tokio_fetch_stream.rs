//! Tokio driver for the streaming FETCH, landing a message body in an
//! `AsyncWrite` instead of a blocking `Write`.
//!
//! [`ImapMessageFetchStream`] declares a yield vocabulary of its own, so
//! it is one of the coroutines the client traits deliberately leave out:
//! where the body goes, and how it gets there, is the consumer's
//! decision. `ImapClientStd::fetch_body_stream` makes it for blocking
//! sinks; this file makes the same one for asynchronous sinks, with the
//! same semantics on both yields that carry body octets:
//!
//! - `BodyChunk` is octets the coroutine already read past the literal
//!   header, appended to the sink as they come.
//! - `WantsStream { len }` hands the socket over for exactly `len`
//!   octets. Reading one more would eat the tagged response, reading
//!   fewer would leave the parser mid-literal, so the copy is
//!   length-bounded rather than a plain `copy`. Resuming with `Some(&[])`
//!   reports a socket that ran short, which the coroutine turns into
//!   `ShortBody` rather than a hang.
//!
//! The body never lands in memory whole either way, which is the point
//! of the coroutine.
//!
//! Run with: `HOST=imap.example.org LOGIN=alice PASSWORD=secret UID=42 cargo run --example tokio_fetch_stream`
//!
//! The body is written to the file named by `OUT`, `body.eml` by
//! default.

use core::num::NonZeroU32;
use std::{env, error::Error, sync::Arc};

use io_imap::{
    codec::fragmentizer::Fragmentizer,
    coroutine::*,
    rfc3501::{fetch_stream::*, select::*},
    session::*,
    types::mailbox::Mailbox,
};
use io_sasl::{mechanism::Sasl, rfc4616::plain::SaslPlainCreds};
use rustls::{ClientConfig, pki_types::ServerName};
use rustls_platform_verifier::ConfigVerifierExt;
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::{TlsConnector, client::TlsStream};

/// Biggest server message the parser accepts, as in the std client.
const FRAGMENTIZER_MAX_MESSAGE_SIZE: u32 = 100 * 1024 * 1024;

/// Read buffer, sized for line-oriented protocol traffic.
const READ_BUFFER_SIZE: usize = 16 * 1024;

/// Buffer for the body transfer. Bulk data rather than line-oriented
/// parsing, so it is far larger than [`READ_BUFFER_SIZE`]: it cuts the
/// syscall and TLS record count on a big message.
const BODY_COPY_BUFFER_SIZE: usize = 128 * 1024;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let host = env::var("HOST")?;
    let port: u16 = env::var("PORT")
        .ok()
        .and_then(|port| port.parse().ok())
        .unwrap_or(993);
    let mailbox = env::var("MAILBOX").unwrap_or_else(|_| String::from("INBOX"));
    let path = env::var("OUT").unwrap_or_else(|_| String::from("body.eml"));
    let uid: NonZeroU32 = env::var("UID")?.parse()?;

    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let sasl = SaslPlainCreds {
        authzid: None,
        authcid: env::var("LOGIN")?,
        passwd: env::var("PASSWORD")?.into(),
    };

    let mut session = TokioSession::open(&host, port, Some(sasl)).await?;

    let mailbox = Mailbox::try_from(mailbox)?;
    let opts = ImapMailboxSelectOptions::default();
    let data = session.run(ImapMailboxSelect::new(mailbox, opts)).await?;

    println!("{} messages in the mailbox", data.exists.unwrap_or(0));

    let file = File::create(&path).await?;

    session.fetch_body_stream(uid, true, file).await?;

    println!("wrote the body of UID {uid} to {path}");

    Ok(())
}

/// The session the fetch runs on: a TLS socket plus the connection-wide
/// parser buffer, the same pair the std client holds.
struct TokioSession {
    stream: TlsStream<TcpStream>,
    fragmentizer: Fragmentizer,
}

impl TokioSession {
    /// Opens an implicit-TLS session, the `imaps://` case.
    ///
    /// Only the TLS transport request is answered here, to keep the
    /// file about the fetch; tokio_session.rs answers all four,
    /// STARTTLS upgrade included.
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
        loop {
            match session.resume(&mut fragmentizer, arg.take()) {
                ImapCoroutineState::Complete(Err(err)) => return Err(err.into()),
                ImapCoroutineState::Complete(Ok(_data)) => {
                    return Ok(Self {
                        stream: stream.expect("session connects before it completes"),
                        fragmentizer,
                    });
                }
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
        }
    }

    /// Runs a standard-yield coroutine, the SELECT this example needs
    /// before it can FETCH.
    ///
    /// This body is what `ImapClientAsync::run` asks for, minus the
    /// Send bounds; implementing the trait instead is one line of
    /// difference and forty commands of gain, and tokio_session.rs does
    /// exactly that. It stays inherent here so this example builds with
    /// no cargo feature at all.
    async fn run<C, T, E>(&mut self, mut coroutine: C) -> Result<T, Box<dyn Error>>
    where
        C: ImapCoroutine<Yield = ImapYield, Return = Result<T, E>>,
        E: Error + 'static,
    {
        let mut buf = [0u8; READ_BUFFER_SIZE];
        let mut arg: Option<&[u8]> = None;

        loop {
            match coroutine.resume(&mut self.fragmentizer, arg.take()) {
                ImapCoroutineState::Complete(Ok(out)) => return Ok(out),
                ImapCoroutineState::Complete(Err(err)) => return Err(err.into()),
                ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
                    let n = self.stream.read(&mut buf).await?;

                    arg = Some(&buf[..n]);
                }
                ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
                    self.stream.write_all(&bytes).await?;
                }
            }
        }
    }

    /// `FETCH <id> (BODY.PEEK[])` streaming the body straight into
    /// `sink`.
    ///
    /// Peek leaves `\Seen` untouched. Returns once the tagged response
    /// is parsed; an id the server does not know completes with an empty
    /// sink.
    async fn fetch_body_stream(
        &mut self,
        id: NonZeroU32,
        uid: bool,
        mut sink: impl AsyncWrite + Unpin,
    ) -> Result<(), Box<dyn Error>> {
        let mut coroutine = ImapMessageFetchStream::new(id, uid);
        let mut buf = [0u8; READ_BUFFER_SIZE];
        let mut body_buf = vec![0u8; BODY_COPY_BUFFER_SIZE];
        let mut arg: Option<&[u8]> = None;

        loop {
            match coroutine.resume(&mut self.fragmentizer, arg.take()) {
                ImapCoroutineState::Complete(Err(err)) => return Err(err.into()),
                ImapCoroutineState::Complete(Ok(())) => {
                    sink.flush().await?;

                    return Ok(());
                }
                ImapCoroutineState::Yielded(ImapMessageFetchStreamYield::WantsRead) => {
                    let n = self.stream.read(&mut buf).await?;

                    arg = Some(&buf[..n]);
                }
                ImapCoroutineState::Yielded(ImapMessageFetchStreamYield::WantsWrite(bytes)) => {
                    self.stream.write_all(&bytes).await?;
                }
                ImapCoroutineState::Yielded(ImapMessageFetchStreamYield::BodyChunk(bytes)) => {
                    sink.write_all(&bytes).await?;
                }
                ImapCoroutineState::Yielded(ImapMessageFetchStreamYield::WantsStream { len }) => {
                    // NOTE: exactly len octets belong to the body, so
                    // the copy is bounded by the announced length rather
                    // than by end of stream, and the socket is handed
                    // back to the parser on the very next octet.
                    let mut remaining = len as usize;
                    let mut short = false;

                    while remaining > 0 {
                        let want = remaining.min(body_buf.len());
                        let n = self.stream.read(&mut body_buf[..want]).await?;

                        if n == 0 {
                            short = true;
                            break;
                        }

                        sink.write_all(&body_buf[..n]).await?;
                        remaining -= n;
                    }

                    // NOTE: an empty resume means the socket ran short of
                    // the announced length; anything else would leave the
                    // coroutine waiting for octets that will never come.
                    arg = short.then_some(&[]);
                }
            }
        }
    }
}
