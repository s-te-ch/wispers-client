{
  description = "Wispers Connect development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { nixpkgs, flake-utils, rust-overlay, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };

        # Core dependencies needed for the Rust library
        coreDeps = with pkgs; [
          rust-bin.stable.latest.default
          cmake
          protobuf
          libclang
        ];

        # Shared environment for all dev shells
        commonEnv = {
          LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";
          # Separate target dir so nix builds don't poison the cmake cache
          # for non-nix builds (and vice versa).
          CARGO_TARGET_DIR = "target/nix";
        };

        mkDevShell = extra: pkgs.mkShell {
          buildInputs = coreDeps ++ extra;
          env = commonEnv;
        };
      in
      {
        devShells = {
          default = mkDevShell [];
          go      = mkDevShell [ pkgs.go ];
          py      = mkDevShell [ pkgs.python313 pkgs.python313Packages.pytest ];
          kt      = mkDevShell [ pkgs.jdk17 pkgs.gradle ];
        };
      }
    );
}
