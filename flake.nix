{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.flake-utils.follows = "flake-utils";
    };

    crane = {
      url = "github:ipetkov/crane";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.flake-utils.follows = "flake-utils";
    };

    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, crane, rust-overlay, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        msrv = builtins.fromTOML (builtins.readFile ./msrv-toolchain.toml);
        rust = pkgs.rust-bin.stable."${msrv.toolchain.channel}".default;
        craneLib = (crane.mkLib pkgs).overrideToolchain rust;
      in
      with pkgs;
      {
        devShell = mkShell {
          buildInputs = [
            openssl
            pkg-config
            rust
          ];
        };
        packages = rec {
          default = rgb-std;
          rgb-std = craneLib.buildPackage {
            strictDeps = true;
            src = ./.;
            cargoExtraArgs = "-p rgb-std";
            doCheck = false;
          };
          rgb-invoice = craneLib.buildPackage {
            strictDeps = true;
            src = ./.;
            cargoExtraArgs = "-p rgb-invoice";
            doCheck = false;
          };
        };
      }
    );
}
