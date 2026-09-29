//! Full std client: pass a URL, let [`ImapClientStd::connect`] open
//! TCP, negotiate TLS, read the greeting + capability list. Requires
//! the `rustls-ring` (or `rustls-aws` / `native-tls`) feature.
//!
//! Run with: `URL=imaps://imap.example.org cargo run --example std_client_full`

use std::{env, error::Error};

use io_imap::client::{ImapClientStd, ImapClientStdConnectOptions};
use url::Url;

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let url = env::var("URL").unwrap();
    let url = Url::parse(&url)?;

    let opts = ImapClientStdConnectOptions::default();
    let (_client, capabilities) = ImapClientStd::connect(&url, opts)?;

    for capability in capabilities {
        println!("{capability:?}");
    }

    Ok(())
}
