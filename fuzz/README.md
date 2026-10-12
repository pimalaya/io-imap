# Fuzzing

Coverage-guided fuzzing of the response side with [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer). Two targets, each feeding arbitrary server bytes, split into reads whose size the first input byte picks, so segmentation is explored too.

The `response` target drives the greeting, STARTTLS, SELECT, EXAMINE, LIST, SEARCH, SORT, FETCH and the single FETCH body stream. Its oracle is that whatever a server sends, a coroutine completes or asks for more, never panics. The greeting and STARTTLS coroutines matter most: they read in plaintext, where anyone on the path speaks.

The `stream_batch` target drives the batched FETCH body stream the way a consumer streams bodies to disk. On top of never panicking, it checks that body octets only flow inside a message and that no body exceeds the configured `max_literal_len`.

cargo-fuzz needs a nightly toolchain (for the `-Z` sanitizer flags). The `fuzz` devShell of the repository flake carries both, nightly via fenix plus cargo-fuzz:

```sh
nix develop .#fuzz --command cargo fuzz run response
nix develop .#fuzz --command cargo fuzz run stream_batch
```

Bound a run with the libFuzzer flags, which come after the `--` separator:

```sh
nix develop .#fuzz --command bash -c "cargo fuzz run response -- -max_total_time=60"
```

libFuzzer saves every interesting new input into `fuzz/corpus/<target>/` (gitignored), and any crash into `fuzz/artifacts/<target>/`, from where it is replayed with `cargo fuzz run <target> fuzz/artifacts/<target>/<file>`.

Off NixOS, `cargo install cargo-fuzz` and a nightly toolchain give the same `cargo fuzz run <target>`.
