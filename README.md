# I/O IMAP [![Documentation](https://img.shields.io/docsrs/io-imap?style=flat&logo=docs.rs&logoColor=white)](https://docs.rs/io-imap/latest/io_imap) [![Matrix](https://img.shields.io/badge/chat-%23pimalaya-blue?style=flat&logo=matrix&logoColor=white)](https://matrix.to/#/#pimalaya:matrix.org) [![Mastodon](https://img.shields.io/badge/news-%40pimalaya-blue?style=flat&logo=mastodon&logoColor=white)](https://fosstodon.org/@pimalaya)

IMAP client library, written in Rust

This library is composed of 3 feature-gated layers:

- Low-level **I/O-free** coroutines: these `no_std`-compatible state machines contain the whole IMAP logic and can be used anywhere
- Mid-level **light client**: a standard, blocking IMAP client using a `Stream: Read + Write`
- High-level **full client**: light client + TCP connections and TLS negotiations handled for you

## Table of contents

- [Features](#features)
- [RFC coverage](#rfc-coverage)
- [Usage](#usage)
  - [Coroutine](#coroutine)
  - [Light client](#light-client)
  - [Full client](#full-client)
- [Examples](#examples)
- [AI disclosure](#ai-disclosure)
- [License](#license)
- [Social](#social)
- [Sponsoring](#sponsoring)

## Features

- **I/O-free** coroutines: `no_std` state machines; no sockets, no async runtime, no `std` required, drive against any blocking, async, or fuzz harness.
- Light standard, blocking client (requires `client` feature)
- Full standard, blocking client with **TLS** support:
  - [Rustls](https://crates.io/crates/rustls) with ring crypto (requires `rustls-ring` feature)
  - [Rustls](https://crates.io/crates/rustls) with aws crypto (requires `rustls-aws` feature)
  - [Native TLS](https://crates.io/crates/native-tls) (requires `native-tls` feature)
- **SASL mechanisms**:
  - `ANONYMOUS`, `LOGIN`, `PLAIN`, `XOAUTH2` and `OAUTHBEARER` built-in
  - `SCRAM-SHA-256` (requires `scram` feature)
- IMAP extensions: `IDLE`, `CONDSTORE`, `QRESYNC` etc (see [RFC coverage](#rfc-coverage))

> [!TIP]
> I/O IMAP is written in [Rust](https://www.rust-lang.org/) and uses [cargo features](https://doc.rust-lang.org/cargo/reference/features.html) to gate backend support. The default feature set is declared in [Cargo.toml](./Cargo.toml) or on [docs.rs](https://docs.rs/crate/io-imap/latest/features).

## RFC coverage

| Module   | What it covers                                                                                                                                                                                                |
|----------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [2177]   | IDLE: push notification extension                                                                                                                                                                             |
| [2971]   | ID: server/client identification extension                                                                                                                                                                    |
| [3501]   | IMAP4rev1: greeting, capability, login/logout, list/lsub/status, create/delete/rename/subscribe/unsubscribe, select/examine/close/check/expunge, fetch/store/search/copy/append, noop, starttls               |
| [3691]   | UNSELECT: discard mailbox state without expunge                                                                                                                                                               |
| [4315]   | UIDPLUS: APPENDUID and COPYUID response codes                                                                                                                                                                 |
| [5161]   | ENABLE: capability activation extension                                                                                                                                                                       |
| [5256]   | SORT and THREAD: server-side message sorting and threading                                                                                                                                                    |
| [6851]   | MOVE: atomic message move extension                                                                                                                                                                           |
| [7162]   | CONDSTORE / QRESYNC: CHANGEDSINCE / VANISHED FETCH modifiers and CONDSTORE / QRESYNC SELECT and EXAMINE parameters for fast incremental resync (obsoletes RFC 4551 CONDSTORE and original RFC 5162 QRESYNC)   |
| [7628]   | OAUTHBEARER: OAuth 2.0 bearer token SASL mechanism; also XOAUTH2                                                                                                                                              |
| [7677]   | SCRAM-SHA-256: SASL SCRAM-SHA-256 mechanism (feature `scram`)                                                                                                                                                 |

[2177]: https://www.rfc-editor.org/rfc/rfc2177
[2971]: https://www.rfc-editor.org/rfc/rfc2971
[3501]: https://www.rfc-editor.org/rfc/rfc3501
[3691]: https://www.rfc-editor.org/rfc/rfc3691
[4315]: https://www.rfc-editor.org/rfc/rfc4315
[5161]: https://www.rfc-editor.org/rfc/rfc5161
[5256]: https://www.rfc-editor.org/rfc/rfc5256
[6851]: https://www.rfc-editor.org/rfc/rfc6851
[7162]: https://www.rfc-editor.org/rfc/rfc7162
[7628]: https://www.rfc-editor.org/rfc/rfc7628
[7677]: https://www.rfc-editor.org/rfc/rfc7677

## Usage

I/O IMAP can be consumed at three layers, depending on how much of the I/O stack you want to own:

- **Coroutines**: `no_std`-friendly state machines. You own the socket and the bytes; the library produces commands and parses responses. Works under any blocking, async, or fuzz harness.
- **Light client** (`client` feature): a `Read + Write` wrapper exposing one method per IMAP command. You still open the socket and negotiate TLS, then hand over a ready stream.
- **Full client** (`rustls-ring` / `rustls-aws` / `native-tls`): TCP, TLS, greeting and SASL handled for you; pass in a URL + SASL config, get back an authenticated session.

Every coroutine implements the `ImapCoroutine` trait (`crate::coroutine`). `resume(&mut Fragmentizer, Option<&[u8]>)` returns `ImapCoroutineState<Yield, Return>`:

- `Yielded(y)`: intermediate progress. The standard `ImapYield` is `WantsRead` (caller reads more bytes and feeds them back; pass `Some(&[])` on EOF) or `WantsWrite(Vec<u8>)` (caller writes these bytes; next resume usually takes `None`). Coroutines that need extra variants declare their own `Yield` enum: `ImapIdle` and `ImapMailboxWatch` add `Event(...)`, `ImapMessageAppend` adds `WantsStream` (caller pumps the declared message octets straight to the socket; resume with `None` once done, `Some(&[])` if the source ran short).
- `Complete(result)`: terminal payload, `Result<Output, Error>`.

The three snippets below all connect to a server (`HOST` / `PORT` env vars; `URL` for the full client), read the greeting, and print the CAPABILITY list. They are the verbatim sources of `cargo run --example <name>`.

### Coroutine

No io-imap features required. The same shape works under async or fuzz harnesses, only the I/O glue changes.

```rust,no_run
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
```

> [!INFO]
> See the tokio-based alternative at [examples/tokio_coroutine.rs](https://github.com/pimalaya/io-imap/blob/master/examples/tokio_coroutine.rs).

### Light client

Enable the `client` feature. `ImapClientStd::new(stream)` wraps any blocking `Read + Write` and exposes one method per IMAP command. You still open the TCP socket, negotiate TLS, authenticate; the client takes it from there.

```toml,ignore
[dependencies]
io-imap = { version = "0.1.0", default-features = false, features = ["client"] }
```

```rust,no_run
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
```

### Full client

Enable one of the TLS feature flags: `rustls-ring` (default), `rustls-aws`, or `native-tls`. `ImapClientStd::connect(url, tls, starttls, sasl, auto_id)` opens `imap://` (plain TCP) or `imaps://` (implicit TLS) via [pimalaya/stream](https://github.com/pimalaya/stream), drives the optional STARTTLS upgrade, reads the greeting + capability list, and runs the chosen SASL mechanism, returning a ready-to-use authenticated client.

```toml,ignore
[dependencies]
io-imap = { version = "0.1.0", default-features = false, features = ["rustls-ring"] }
```

```rust,no_run
use std::{env, error::Error};

use io_imap::client::ImapClientStd;
use pimalaya_stream::{sasl::Sasl, tls::Tls};
use url::Url;

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let url = env::var("URL").unwrap();
    let url = Url::parse(&url)?;
    let tls = Tls::default();

    let (_client, capabilities) = ImapClientStd::connect(&url, &tls, false, None::<Sasl>, None)?;

    for capability in capabilities {
        println!("{capability:?}");
    }

    Ok(())
}
```

The `sasl` argument is `Option<impl Into<Sasl>>`, so any of the per-mechanism structs (`SaslLogin`, `SaslPlain`, `SaslAnonymous`, `SaslOauthbearer`, `SaslXoauth2`, `SaslScramSha256` behind the `scram` feature) can be passed in `Some(...)` directly without wrapping in a `Sasl` variant.

## Examples

See the complete examples at [./examples](https://github.com/pimalaya/io-imap/blob/master/examples).

Have also a look at real-world projects built on top of this library:

- [Himalaya CLI](https://github.com/pimalaya/himalaya): CLI to manage emails
- [Himalaya TUI](https://github.com/pimalaya/himalaya-tui): TUI to manage emails
- [Neverest](https://github.com/pimalaya/neverest): CLI to synchronize emails
- [Mirador](https://github.com/pimalaya/mirador): CLI to watch mailbox changes and fire hooks on every event
- [Sirup](https://github.com/pimalaya/sirup): CLI to spawn pre-authenticated IMAP/SMTP sessions and expose them via Unix sockets

## AI disclosure

This project is developed with AI assistance. This section documents how, so users and downstream packagers can make informed decisions.

- **Tools**: Claude Code (Anthropic), Opus 4.7, invoked locally with a persistent project-scoped memory and a small set of repo-specific rules.

- **Used for**: Refactors, mechanical multi-file edits, boilerplate (feature gates, error enums, derive macros, trait impls), test scaffolding, doc polish, exploratory design conversations.

- **Not used for**: Engineering, critical code, git manipulation (commit, merge, rebase…), real-world tests.

- **Verification**: Every AI-assisted change is read, compiled, tested, and formatted before commit (`nix develop --command cargo check / cargo test / cargo
fmt`). Behavioural correctness is verified against the relevant RFC or upstream spec, not assumed from the model output. Tests are never adjusted to fit
AI-generated code; the code is adjusted to fit correct behaviour.

- **Limitations**: AI models occasionally produce code that compiles and passes tests but is subtly wrong: off-by-one errors, missed edge cases, plausible
but nonexistent APIs, stale RFC references. The verification workflow catches most of this; it does not catch all of it. Bug reports are welcome and taken
seriously.

- **Last reviewed**: 29/05/2026

## License

This project is licensed under either of:

- [MIT license](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

at your option.

## Social

- Chat on [Matrix](https://matrix.to/#/#pimalaya:matrix.org)
- News on [Mastodon](https://fosstodon.org/@pimalaya) or [RSS](https://fosstodon.org/@pimalaya.rss)
- Mail at [pimalaya.org@posteo.net](mailto:pimalaya.org@posteo.net)

## Sponsoring

[![nlnet](https://nlnet.nl/logo/banner-160x60.png)](https://nlnet.nl/)

Special thanks to the [NLnet foundation](https://nlnet.nl/) and the [European Commission](https://www.ngi.eu/) that have been financially supporting the project for years:

- 2022 → 2023: [NGI Assure](https://nlnet.nl/project/Himalaya/)
- 2023 → 2024: [NGI Zero Entrust](https://nlnet.nl/project/Pimalaya/)
- 2024 → 2026: [NGI Zero Core](https://nlnet.nl/project/Pimalaya-PIM/)
- *2027 in preparation…*

If you appreciate the project, feel free to donate using one of the following providers:

[![GitHub](https://img.shields.io/badge/-GitHub%20Sponsors-fafbfc?logo=GitHub%20Sponsors)](https://github.com/sponsors/soywod)
[![Ko-fi](https://img.shields.io/badge/-Ko--fi-ff5e5a?logo=Ko-fi&logoColor=ffffff)](https://ko-fi.com/soywod)
[![Buy Me a Coffee](https://img.shields.io/badge/-Buy%20Me%20a%20Coffee-ffdd00?logo=Buy%20Me%20A%20Coffee&logoColor=000000)](https://www.buymeacoffee.com/soywod)
[![Liberapay](https://img.shields.io/badge/-Liberapay-f6c915?logo=Liberapay&logoColor=222222)](https://liberapay.com/soywod)
[![thanks.dev](https://img.shields.io/badge/-thanks.dev-000000?logo=data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjQuMDk3IiBoZWlnaHQ9IjE3LjU5NyIgY2xhc3M9InctMzYgbWwtMiBsZzpteC0wIHByaW50Om14LTAgcHJpbnQ6aW52ZXJ0IiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjxwYXRoIGQ9Ik05Ljc4MyAxNy41OTdINy4zOThjLTEuMTY4IDAtMi4wOTItLjI5Ny0yLjc3My0uODktLjY4LS41OTMtMS4wMi0xLjQ2Mi0xLjAyLTIuNjA2di0xLjM0NmMwLTEuMDE4LS4yMjctMS43NS0uNjc4LTIuMTk1LS40NTItLjQ0Ni0xLjIzMi0uNjY5LTIuMzQtLjY2OUgwVjcuNzA1aC41ODdjMS4xMDggMCAxLjg4OC0uMjIyIDIuMzQtLjY2OC40NTEtLjQ0Ni42NzctMS4xNzcuNjc3LTIuMTk1VjMuNDk2YzAtMS4xNDQuMzQtMi4wMTMgMS4wMjEtMi42MDZDNS4zMDUuMjk3IDYuMjMgMCA3LjM5OCAwaDIuMzg1djEuOTg3aC0uOTg1Yy0uMzYxIDAtLjY4OC4wMjctLjk4LjA4MmExLjcxOSAxLjcxOSAwIDAgMC0uNzM2LjMwN2MtLjIwNS4xNTYtLjM1OC4zODQtLjQ2LjY4Mi0uMTAzLjI5OC0uMTU0LjY4Mi0uMTU0IDEuMTUxVjUuMjNjMCAuODY3LS4yNDkgMS41ODYtLjc0NSAyLjE1NS0uNDk3LjU2OS0xLjE1OCAxLjAwNC0xLjk4MyAxLjMwNXYuMjE3Yy44MjUuMyAxLjQ4Ni43MzYgMS45ODMgMS4zMDUuNDk2LjU3Ljc0NSAxLjI4Ny43NDUgMi4xNTR2MS4wMjFjMCAuNDcuMDUxLjg1NC4xNTMgMS4xNTIuMTAzLjI5OC4yNTYuNTI1LjQ2MS42ODIuMTkzLjE1Ny40MzcuMjYuNzMyLjMxMi4yOTUuMDUuNjIzLjA3Ni45ODQuMDc2aC45ODVabTE0LjMxNC03LjcwNmgtLjU4OGMtMS4xMDggMC0xLjg4OC4yMjMtMi4zNC42NjktLjQ1LjQ0NS0uNjc3IDEuMTc3LS42NzcgMi4xOTVWMTQuMWMwIDEuMTQ0LS4zNCAyLjAxMy0xLjAyIDIuNjA2LS42OC41OTMtMS42MDUuODktMi43NzQuODloLTIuMzg0di0xLjk4OGguOTg0Yy4zNjIgMCAuNjg4LS4wMjcuOTgtLjA4LjI5Mi0uMDU1LjUzOC0uMTU3LjczNy0uMzA4LjIwNC0uMTU3LjM1OC0uMzg0LjQ2LS42ODIuMTAzLS4yOTguMTU0LS42ODIuMTU0LTEuMTUydi0xLjAyYzAtLjg2OC4yNDgtMS41ODYuNzQ1LTIuMTU1LjQ5Ny0uNTcgMS4xNTgtMS4wMDQgMS45ODMtMS4zMDV2LS4yMTdjLS44MjUtLjMwMS0xLjQ4Ni0uNzM2LTEuOTgzLTEuMzA1LS40OTctLjU3LS43NDUtMS4yODgtLjc0NS0yLjE1NXYtMS4wMmMwLS40Ny0uMDUxLS44NTQtLjE1NC0xLjE1Mi0uMTAyLS4yOTgtLjI1Ni0uNTI2LS40Ni0uNjgyYTEuNzE5IDEuNzE5IDAgMCAwLS43MzctLjMwNyA1LjM5NSA1LjM5NSAwIDAgMC0uOTgtLjA4MmgtLjk4NFYwaDIuMzg0YzEuMTY5IDAgMi4wOTMuMjk3IDIuNzc0Ljg5LjY4LjU5MyAxLjAyIDEuNDYyIDEuMDIgMi42MDZ2MS4zNDZjMCAxLjAxOC4yMjYgMS43NS42NzggMi4xOTUuNDUxLjQ0NiAxLjIzMS42NjggMi4zNC42NjhoLjU4N3oiIGZpbGw9IiNmZmYiLz48L3N2Zz4=)](https://thanks.dev/soywod)
[![PayPal](https://img.shields.io/badge/-PayPal-0079c1?logo=PayPal&logoColor=ffffff)](https://www.paypal.com/paypalme/soywod)
