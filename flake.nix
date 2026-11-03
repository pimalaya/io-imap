{
  description = "IMAP client library for Rust";

  inputs = {
    nixpkgs = {
      url = "github:nixos/nixpkgs/nixos-26.05";
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
