//! Blocking, rustls-only example: open a TCP+TLS connection by hand, resume
//! [`ImapGreetingGet`] manually, print the server's CAPABILITY list. No io-imap
//! features required.
//!
//! Run with: `HOST=imap.example.org cargo run --example std_coroutine`

use std::{
    env,
    error::Error,
    io::{Read, Write},
    net::TcpStream,
    sync::Arc,
};

use io_imap::{
    codec::fragmentizer::Fragmentizer,
    coroutine::{ImapCoroutine, ImapCoroutineState, ImapYield},
    rfc3501::greeting::{ImapGreetingGet, ImapGreetingGetOptions},
};
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
    let mut stream = StreamOwned::new(tls, sock);

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
                stream.write_all(&bytes)?;
            }
            ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
                let n = stream.read(&mut buf)?;
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
