# Contributing guide

Thank you for investing your time in contributing to I/O IMAP.

Whether you are a human or an AI agent, read these in order before touching the code:

1. the [Pimalaya README](https://github.com/pimalaya) for what the project is and how its repositories stack;
2. the [Pimalaya CONTRIBUTING](https://github.com/pimalaya/.github/blob/master/CONTRIBUTING.md) guide, which chains to the shared architecture and guidelines;
3. the inline header documentation, starting with src/lib.rs: it is the architecture document of this crate;
4. the docs/ folder for the development history and living plans.

Everything below documents only what differs from the Pimalaya standards.

## Feature matrix

On top of the standard layers, io-imap gates the SCRAM-SHA-256 mechanism behind the scram feature (it pulls the hmac, pbkdf2, rand and sha2 crates); the default set is scram plus rustls-ring. Check every layer:

```sh
cargo build --no-default-features                            # coroutines only, no std leak
cargo build --no-default-features --features client          # light client, no TLS deps
cargo build --no-default-features --features client,scram    # light client + SCRAM-SHA-256
cargo build                                                  # full client (scram + rustls-ring)
```

## End-to-end tests

Besides the unit and doc tests, three ignored end-to-end tests run the full coroutine flow against real servers. The Stalwart one is self-contained: tests/stalwart.sh spawns a pre-provisioned local instance in a container, then:

```sh
cargo test --test stalwart -- --ignored
```

The Fastmail and Gmail ones need real credentials in the environment; see the doc comment of each test file:

```sh
FASTMAIL_EMAIL=user@fastmail.com FASTMAIL_APP_PASSWORD=xxx cargo test --test fastmail -- --ignored
GMAIL_EMAIL=user@gmail.com GMAIL_APP_PASSWORD=xxx cargo test --test gmail -- --ignored
```
