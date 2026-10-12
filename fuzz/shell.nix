# A dedicated fuzzing shell: a nightly toolchain (cargo-fuzz needs the `-Z`
# sanitizer flags stable rustc rejects) plus cargo-fuzz itself, via fenix, so no
# rustup and no nix-ld shim are needed. It is exposed as the `fuzz` devShell of
# the repository flake, which pins both nixpkgs and fenix:
#
#   nix develop .#fuzz --command cargo fuzz run response
#
# Called directly, it falls back to the nixpkgs channel of the caller, which
# only exists where NIX_PATH is set:
#
#   nix-shell fuzz/shell.nix --run "cargo fuzz run response"
{
  nixpkgs ? <nixpkgs>,
  system ? builtins.currentSystem,
  pkgs ? import nixpkgs { inherit system; },
  fenix ? import (fetchTarball "https://github.com/nix-community/fenix/archive/monthly.tar.gz") { },
}:

let
  inherit (pkgs) cargo-fuzz stdenv;

in
pkgs.mkShell {
  packages = [
    fenix.default.toolchain
    cargo-fuzz
  ];

  # The libFuzzer/ASan binary cargo-fuzz builds links libstdc++ dynamically, and
  # NixOS has no global libstdc++.so.6; point the loader at the toolchain's copy.
  shellHook = ''
    export LD_LIBRARY_PATH="${stdenv.cc.cc.lib}/lib''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
  '';
}
