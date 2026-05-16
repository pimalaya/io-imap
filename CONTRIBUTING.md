# Contributing guide

Thank you for investing your time in contributing to the I/O IMAP project.

## Development

The development environment is managed by [Nix](https://nixos.org/download.html).
Running `nix-shell` will spawn a shell with everything you need to get started with the lib.

If you do not want to use Nix, you can either use [rustup](https://rust-lang.github.io/rustup/index.html):

```
rustup update
```

or install manually the following dependencies:

- [cargo](https://doc.rust-lang.org/cargo/)
- [rustc](https://doc.rust-lang.org/stable/rustc/platform-support.html) (`>= 1.87`)

## Build

```
cargo build
```

## Test

```
cargo test
```

## Override dependencies

All Pimalaya crates use `[patch.crates-io]` to point to sibling directories.
If you want to build io-imap against a locally modified dependency (e.g. `imap-codec`), add the following to `Cargo.toml`:

```toml
[patch.crates-io]
imap-codec.path = "/path/to/imap-codec"
```

## Commit style

I/O IMAP follows the [conventional commits specification](https://www.conventionalcommits.org/en/v1.0.0/#summary).
