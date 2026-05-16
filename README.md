# I/O IMAP [![Documentation](https://img.shields.io/docsrs/io-imap?style=flat&logo=docs.rs&logoColor=white)](https://docs.rs/io-imap/latest/io_imap) [![Matrix](https://img.shields.io/badge/chat-%23pimalaya-blue?style=flat&logo=matrix&logoColor=white)](https://matrix.to/#/#pimalaya:matrix.org) [![Mastodon](https://img.shields.io/badge/news-%40pimalaya-blue?style=flat&logo=mastodon&logoColor=white)](https://fosstodon.org/@pimalaya)

IMAP client library, written in Rust

## Table of contents

- [Features](#features)
- [RFC coverage](#rfc-coverage)
- [Examples](#examples)
  - [As a no-std coroutine library](#as-a-no-std-coroutine-library)
  - [As a light std client (BYO stream)](#as-a-light-std-client-byo-stream)
  - [As a full std client (TCP + TLS)](#as-a-full-std-client-tcp--tls)
- [More examples](#more-examples)
- [License](#license)
- [Social](#social)
- [Sponsoring](#sponsoring)

## Features

- **I/O-free** coroutines: every IMAP command is exposed as a `resume(arg: Option<&[u8]>)` state machine. No sockets, no async runtime, no `std` required. Drive against any blocking, async, or fuzz harness.
- **Standard, blocking client**:
  - Light client (requires `client` feature): `ImapClientStd::new(stream)` wraps a connected `Read + Write` stream and exposes one method per coroutine, with the long-lived `ImapContext` managed for you. You still own TCP / TLS / STARTTLS.
  - Full std client (requires `rustls-ring`, `rustls-aws`, or `native-tls` feature): `ImapClientStd::connect(url, tls, starttls, sasl)` opens `imap://` / `imaps://` URLs via [pimalaya/stream](https://github.com/pimalaya/stream), drives the optional STARTTLS upgrade, and runs the chosen SASL mechanism, returning a ready-to-use authenticated client.
- **SASL mechanisms**:
  - `LOGIN`, `PLAIN`, `ANONYMOUS`, `XOAUTH2` and `OAUTHBEARER` built-in
  - `SCRAM-SHA-256` (requires `scram` feature)

*The `io-imap` library is written in [Rust](https://www.rust-lang.org/), and relies on [cargo features](https://doc.rust-lang.org/cargo/reference/features.html) to enable or disable functionalities. Default features can be found in the `features` section of the [`Cargo.toml`](https://github.com/pimalaya/io-imap/blob/master/Cargo.toml), or on [docs.rs](https://docs.rs/crate/io-imap/latest/features).*

## RFC coverage

This library implements IMAP as I/O-agnostic coroutines: no sockets, no async runtime, no `std` required.

| Module   | What it covers                                                                                                            |
|----------|---------------------------------------------------------------------------------------------------------------------------|
| [2177]   | IDLE: push notification extension                                                                                         |
| [2971]   | ID: server/client identification extension                                                                                |
| [3501]   | IMAP4rev1: greeting, capability, login, logout, select, list, fetch, store, search, copy, append, expunge, noop, starttls |
| [3691]   | UNSELECT: discard mailbox state without expunge                                                                           |
| [4315]   | UIDPLUS: APPENDUID and COPYUID response codes                                                                             |
| [5161]   | ENABLE: capability activation extension                                                                                   |
| [5256]   | SORT and THREAD: server-side message sorting and threading                                                                |
| [6851]   | MOVE: atomic message move extension                                                                                       |
| [7628]   | OAUTHBEARER: OAuth 2.0 bearer token SASL mechanism; also XOAUTH2                                                          |
| [7677]   | SCRAM-SHA-256: SASL SCRAM-SHA-256 mechanism (feature `scram`)                                                             |

[2177]: https://www.rfc-editor.org/rfc/rfc2177
[2971]: https://www.rfc-editor.org/rfc/rfc2971
[3501]: https://www.rfc-editor.org/rfc/rfc3501
[3691]: https://www.rfc-editor.org/rfc/rfc3691
[4315]: https://www.rfc-editor.org/rfc/rfc4315
[5161]: https://www.rfc-editor.org/rfc/rfc5161
[5256]: https://www.rfc-editor.org/rfc/rfc5256
[6851]: https://www.rfc-editor.org/rfc/rfc6851
[7628]: https://www.rfc-editor.org/rfc/rfc7628
[7677]: https://www.rfc-editor.org/rfc/rfc7677

## Examples

`io-imap` can be consumed three ways, depending on how much of the I/O stack you want to own. Each mode is gated by cargo features.

Whichever mode you pick, every coroutine exposes `resume(arg: Option<&[u8]>)` returning a result enum with four shapes:

- `WantsRead`: caller reads more bytes from the socket and feeds them back on the next call. Pass `Some(&[])` to signal EOF.
- `WantsWrite(Vec<u8>)`: caller writes these bytes to the socket. The next call typically passes `None`.
- `Ok { … }`: terminal success.
- `Err { … }`: terminal failure.

### As a no-std coroutine library

No features required: works in `#![no_std]`, no sockets, no async runtime. You own the loop and the bytes; the library only produces command bytes and consumes server responses.

Read the IMAP greeting against a blocking TCP socket (the same shape works under async, fuzzing, or in-memory replay):

```rust,ignore
use std::{io::Read, net::TcpStream};

use io_imap::{context::ImapContext, rfc3501::greeting::*};

let mut stream = TcpStream::connect("imap.example.com:143").unwrap();
let mut buf = [0u8; 16 * 1024];

let mut coroutine = ImapGreetingGet::new(ImapContext::new());
let mut arg: Option<&[u8]> = None;

let context = loop {
    match coroutine.resume(arg.take()) {
        ImapGreetingGetResult::Ok { context } => break context,
        ImapGreetingGetResult::WantsRead => {
            let n = stream.read(&mut buf).unwrap();
            arg = Some(&buf[..n]);
        }
        ImapGreetingGetResult::Err { err, .. } => panic!("{err}"),
    }
};
```

Drive a multi-step command (LIST) the same way:

```rust,ignore
use std::{io::{Read, Write}, net::TcpStream};

use imap_codec::imap_types::mailbox::{ListMailbox, Mailbox};
use io_imap::{context::ImapContext, rfc3501::list::*};

# let mut stream = TcpStream::connect("imap.example.com:143").unwrap();
# let mut buf = [0u8; 16 * 1024];
# let context = ImapContext::new();
let reference = Mailbox::try_from("").unwrap();
let pattern = ListMailbox::try_from("*").unwrap();
let mut coroutine = ImapMailboxList::new(context, reference, pattern);
let mut arg: Option<&[u8]> = None;

let mailboxes = loop {
    match coroutine.resume(arg.take()) {
        ImapMailboxListResult::Ok { mailboxes, .. } => break mailboxes,
        ImapMailboxListResult::WantsRead => {
            let n = stream.read(&mut buf).unwrap();
            arg = Some(&buf[..n]);
        }
        ImapMailboxListResult::WantsWrite(bytes) => {
            stream.write_all(&bytes).unwrap();
            arg = None;
        }
        ImapMailboxListResult::Err { err, .. } => panic!("{err}"),
    }
};

for (mailbox, _delimiter, _flags) in mailboxes {
    println!("{mailbox:?}");
}
```

### As a light std client (BYO stream)

Enable the `client` feature. `ImapClientStd::new(stream)` wraps any blocking `Read + Write` and exposes one method per IMAP command. You still open the TCP socket, run TLS / STARTTLS yourself, and hand over a ready-to-talk stream; the client takes it from there.

```toml,ignore
[dependencies]
io-imap = { version = "0.0.1", default-features = false, features = ["client"] }
```

```rust,ignore
use std::net::TcpStream;

use io_imap::client::ImapClientStd;

let stream = TcpStream::connect("imap.example.com:143")?;
let mut client = ImapClientStd::new(stream);

let capabilities = client.greeting()?;
println!("server capabilities: {capabilities:?}");

let reference = "".try_into()?;
let pattern = "*".try_into()?;

for (mailbox, _, _) in client.list(reference, pattern)? {
    println!("{mailbox:?}");
}
```

### As a full std client (TCP + TLS)

Enable one of the TLS feature flags: `rustls-ring` (default), `rustls-aws`, or `native-tls`. `ImapClientStd::connect(url, tls, starttls, sasl)` opens `imap://` (plain TCP) or `imaps://` (implicit TLS) via [pimalaya/stream](https://github.com/pimalaya/stream), drives the optional STARTTLS upgrade, reads the greeting + capability list, and runs the chosen SASL mechanism, returning a ready-to-use authenticated client.

```toml,ignore
[dependencies]
io-imap = "0.0.1" # rustls-ring is enabled by default
```

```rust,ignore
use io_imap::client::ImapClientStd;
use pimalaya_stream::{sasl::{Sasl, SaslLogin}, tls::Tls};
use secrecy::SecretString;
use url::Url;

let url = Url::parse("imaps://imap.example.com")?;
let tls = Tls::default();
let sasl = Sasl::Login(SaslLogin {
    username: "alice@example.com".into(),
    password: SecretString::from("hunter2".to_owned()),
});

let mut client = ImapClientStd::connect(&url, &tls, false, Some(sasl))?;

// session is already authenticated; issue further commands directly
for (mailbox, _, _) in client.list("".try_into()?, "*".try_into()?)? {
    println!("{mailbox:?}");
}
```

For mechanisms not yet reachable through `connect` (OAUTHBEARER / XOAUTH2 / SCRAM-SHA-256), use `ImapClientStd::new(stream)` (mode 2) and drive the relevant coroutine directly.

*See complete examples at [./examples](https://github.com/pimalaya/io-imap/blob/master/examples).*

## More examples

Have a look at projects built on top of this library:

- [himalaya](https://github.com/pimalaya/himalaya): CLI to manage emails

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
[![thanks.dev](https://img.shields.io/badge/-thanks.dev-000000?logo=data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjQuMDk3IiBoZWlnaHQ9IjE3LjU5NyIgY2xhc3M9InctMzYgbWwtMiBsZzpteC0wIHByaW50Om14LTAgcHJpbnQ6aW52ZXJ0IiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjxwYXRoIGQ9Ik05Ljc4MyAxNy41OTdINy4zOThjLTEuMTY4IDAtMi4wOTItLjI5Ny0yLjc3My0uODktLjY4LS41OTMtMS4wMi0xLjQ2Mi0xLjAyLTIuNjA2di0xLjM0NmMwLTEuMDE4LS4yMjctMS43NS0uNjc4LTIuMTk1LS40NTItLjQ0Ni0xLjIzMi0uNjY5LTIuMzQtLjY2OUgwVjcuNzA1aC41ODdjMS4xMDggMCAxLjg4OC0uMjIyIDIuMzQtLjY2OC40NTEtLjQ0Ni42NzctMS4xNzcuNjc3LTIuMTk1VjMuNDk2YzAtMS4xNDQuMzQtMi4wMTMgMS4wMjEtMi42MDZDNS4zMDUuMjk3IDYuMjMgMCA3LjM5OCAwaDIuMzg1djEuOTg3aC0uOTg1Yy0uMzYxIDAtLjY4OC4wMjctLjk4LjA4MmExLjcxOSAxLjcxOSAwIDAgMC0uNzM2LjMwN2MtLjIwNS4xNTYtLjM1OC4zODQtLjQ2LjY4Mi0uMTAzLjI5OC0uMTU0LjY4Mi0uMTU0IDEuMTUxVjUuMjNjMCAuODY3LS4yNDkgMS41ODYtLjc0NSAyLjE1NS0uNDk3LjU2OS0xLjE1OCAxLjAwNC0xLjk4MyAxLjMwNXYuMjE3Yy44MjUuMyAxLjQ4Ni43MzYgMS45ODMgMS4zMDUuNDk2LjU3Ljc0NSAxLjI4Ny43NDUgMi4xNTR2MS4wMjFjMCAuNDcuMDUxLjg1NC4xNTMgMS4xNTIuMTAzLjI5OC4yNTYuNTI1LjQ2MS42ODIuMTkzLjE1Ny40MzcuMjYuNzMyLjMxMi4yOTUuMDUuNjIzLjA3Ni45ODQuMDc2aC45ODVabTE0LjMxNC03LjcwNmgtLjU4OGMtMS4xMDggMC0xLjg4OC4yMjMtMi4zNC42NjktLjQ1LjQ0Ni0uNjc3IDEuMTc3LS42NzcgMi4xOTVWMTQuMWMwIDEuMTQ0LS4zNCAyLjAxMy0xLjAyIDIuNjA2LS42OC41OTMtMS42MDUuODloLTIuMzg0di0xLjk4OGguOTg0Yy4zNjIgMCAuNjg4LS4wMjcuOTgtLjA4LjI5Mi0uMDU1LjUzOC0uMTU3LjczNy0uMzA4LjIwNC0uMTU3LjM1OC0uMzg0LjQ2LS42ODIuMTAzLS4yOTguMTU0LS42ODIuMTU0LTEuMTUydi0xLjAyYzAtLjg2OC4yNDgtMS41ODYuNzQ1LTIuMTU1LjQ5Ny0uNTcgMS4xNTgtMS4wMDQgMS45ODMtMS4zMDV2LS4yMTdjLS44MjUtLjMwMS0xLjQ4Ni0uNzM2LTEuOTgzLTEuMzA1LS40OTctLjU3LS43NDUtMS4yODgtLjc0NS0yLjE1NXYtMS4wMmMwLS40Ny0uMDUxLS44NTQtLjE1NC0xLjE1Mi0uMTAyLS4yOTgtLjI1Ni0uNTI2LS40Ni0uNjgyYTEuNzE5IDEuNzE5IDAgMCAwLS43MzctLjMwNyA1LjM5NSA1LjM5NSAwIDAgMC0uOTgtLjA4MmgtLjk4NFYwaDIuMzg0YzEuMTY5IDAgMi4wOTMuMjk3IDIuNzc0Ljg5LjY4LjU5MyAxLjAyIDEuNDYyIDEuMDIgMi42MDZ2MS4zNDZjMCAxLjAxOC4yMjYgMS43NS42NzggMi4xOTUuNDUxLjQ0NiAxLjIzMS42NjggMi4zNC42NjhoLjU4N3oiIGZpbGw9IiNmZmYiLz48L3N2Zz4=)](https://thanks.dev/soywod)
[![PayPal](https://img.shields.io/badge/-PayPal-0079c1?logo=PayPal&logoColor=ffffff)](https://www.paypal.com/paypalme/soywod)
