//! Light std client: build the TLS stream yourself, wrap it in an
//! [`ImapStream`], hand it off to [`ImapClientStd::new`], let the client
//! read the greeting. Requires the `client` feature.
//!
//! Run with: `HOST=imap.example.org cargo run --example std_client_light`

use std::{
    any::Any,
    env,
    error::Error,
    io::{self, Read, Write},
    net::TcpStream,
    sync::Arc,
    time::Duration,
};

use io_imap::client::{ImapClient, ImapClientStd, ImapStream};
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use rustls_platform_verifier::ConfigVerifierExt;

/// A caller-owned TLS stream taught to be an [`ImapStream`]. Read and
/// write forward to the rustls stream; the read timeout forwards to the
/// underlying socket, so the mailbox watch worker can wake to poll its
/// shutdown flag during a silent IDLE.
struct TlsStream(StreamOwned<ClientConnection, TcpStream>);

impl Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl ImapStream for TlsStream {
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.0.get_ref().set_read_timeout(timeout)
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let host = env::var("HOST").unwrap();
    let port: u16 = env::var("PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(993);

    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let config = Arc::new(ClientConfig::with_platform_verifier()?);
    let server_name = rustls::pki_types::ServerName::try_from(host.as_str())?.to_owned();
    let tls = ClientConnection::new(config, server_name)?;
    let sock = TcpStream::connect((host.as_str(), port))?;
    let stream = TlsStream(StreamOwned::new(tls, sock));

    let mut client = ImapClientStd::new(stream);
    let capabilities = client.greeting()?.capability;

    for capability in capabilities {
        println!("{capability:?}");
    }

    Ok(())
}
