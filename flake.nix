{
  inputs = {
    nixpkgs.url = "nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
    naersk.url = "github:nix-community/naersk";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, flake-utils, naersk, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        skattemelding-overlay = (final: prev: {
          skattemelding = (final.callPackage ./. { } // {
            backend = final.callPackage ./backend.nix { inherit naersk; };
          });
        });

        overlays = [ (import rust-overlay) skattemelding-overlay ];

        pkgs = import nixpkgs {
          inherit system overlays;
          config.allowUnfree = true;
        };

      in with pkgs; rec {
        apps = { dev = skattemelding.dev; };
        packages = {
          image = skattemelding.image;
          backend = skattemelding.backend.skattemelding;
        };
        defaultPackage = packages.image;
        checks = packages;
        devShell = skattemelding.backend.shell;
      });
}