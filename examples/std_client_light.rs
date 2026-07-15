//! Light std client: build the TLS stream yourself, hand it off to
//! [`ImapClientStd::new`], let the client read the greeting.
//! Requires the `client` feature.
//!
//! Run with: `HOST=imap.example.org cargo run --example std_client_light`

use std::{env, error::Error, net::TcpStream, sync::Arc};

use io_imap::client::ImapClientStd;
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use rustls_platform_verifier::ConfigVerifierExt;

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
    let stream = StreamOwned::new(tls, sock);

    let mut client = ImapClientStd::new(stream);
    let capabilities = client.greeting()?;

    for capability in capabilities {
        println!("{capability:?}");
    }

    Ok(())
}
