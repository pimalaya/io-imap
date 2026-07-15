{
  nixpkgs ? <nixpkgs>,
  system ? builtins.currentSystem,
  pkgs ? import nixpkgs { inherit system; },
  pimalaya ? import (fetchTarball "https://github.com/pimalaya/nix/archive/master.tar.gz"),
  fenix ? import (fetchTarball "https://github.com/nix-community/fenix/archive/monthly.tar.gz") { },
}:

let
  inherit (pkgs)
    krb5
    openssl
    pkg-config
    cargo-deny
    llvmPackages
    glibc
    ;
  shell = pimalaya.mkShell {
    inherit
      nixpkgs
      system
      pkgs
      fenix
      ;
  };

in
shell.overrideAttrs (prev: {
  LIBCLANG_PATH = "${llvmPackages.libclang.lib}/lib";
  BINDGEN_EXTRA_CLANG_ARGS = "-isystem ${glibc.dev}/include";

  nativeBuildInputs = (prev.nativeBuildInputs or [ ]) ++ [
    pkg-config
  ];

  buildInputs = (prev.buildInputs or [ ]) ++ [
    krb5
    openssl
    cargo-deny
  ];
})
