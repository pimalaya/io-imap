{
  description = "IMAP client library for Rust";

  inputs = {
    nixpkgs = {
      url = "github:nixos/nixpkgs/nixos-25.11";
    };
    fenix = {
      url = "github:nix-community/fenix/monthly";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    pimalaya = {
      url = "github:pimalaya/nix";
      flake = false;
    };
  };

  outputs =
    inputs:
    let
      inherit (inputs.nixpkgs) lib;

      outputs = (import inputs.pimalaya).mkFlakeOutputs inputs {
        shell = ./shell.nix;
      };

      # The fuzz targets need a nightly toolchain and cargo-fuzz, which
      # the standard shell does not carry. Exposing them as a second
      # devShell keeps the nixpkgs and fenix pinned by this flake.
      fuzzShell = system: {
        fuzz = import ./fuzz/shell.nix {
          inherit (inputs) nixpkgs;
          inherit system;
          fenix = inputs.fenix.packages.${system};
        };
      };

    in
    outputs
    // {
      devShells = lib.mapAttrs (system: shells: shells // fuzzShell system) outputs.devShells;
    };
}
