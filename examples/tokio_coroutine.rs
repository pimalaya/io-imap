//! Async, tokio-rustls example: same shape as `std_coroutine` but on
//! top of `tokio::net::TcpStream` + `tokio_rustls::TlsConnector`. The
//! coroutine itself is identical; only the I/O glue changes.
//!
//! Run with: `HOST=imap.example.org cargo run --example tokio_coroutine`

use std::{env, error::Error, sync::Arc};

use io_imap::{
    codec::fragmentizer::Fragmentizer,
    coroutine::{ImapCoroutine, ImapCoroutineState, ImapYield},
    rfc3501::greeting::{ImapGreetingGet, ImapGreetingGetOptions},
};
use rustls::{ClientConfig, pki_types::ServerName};
use rustls_platform_verifier::ConfigVerifierExt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::TlsConnector;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
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
    let connector = TlsConnector::from(config);
    let server_name = ServerName::try_from(host.as_str())?.to_owned();
    let sock = TcpStream::connect((host.as_str(), port)).await?;
    let mut stream = connector.connect(server_name, sock).await?;

    let mut fragmentizer = Fragmentizer::new(50 * 1024 * 1024);
    let mut buf = [0u8; 4096];

    let opts = ImapGreetingGetOptions {
        ensure_capabilities: true,
    };
    let mut coroutine = ImapGreetingGet::new(opts);
    let mut arg = None;

    let greeting = loop {
        match coroutine.resume(&mut fragmentizer, arg.take()) {
            ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
                stream.write_all(&bytes).await?;
            }
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
                let n = stream.read(&mut buf).await?;
                arg = Some(&buf[..n]);
            }
            ImapCoroutineState::Complete(Ok(greeting)) => break greeting,
            ImapCoroutineState::Complete(Err(err)) => return Err(err.into()),
        }
    };

    for capability in greeting.capability {
        println!("{capability:?}");
    }

    Ok(())
}
