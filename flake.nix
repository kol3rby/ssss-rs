{
  description = "A flake for ssss-rs (a Rust port of Shamir's Secret Sharing Scheme)";

  inputs = {
    # Re-pinned from the original's nixos-21.05 (Rust too old) to a current
    # nixpkgs so rustPlatform.buildRustPackage builds this crate.
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let pkgs = import nixpkgs { inherit system; };
      in {
        packages.ssss = pkgs.callPackage ./default.nix { };
        packages.default = self.packages.${system}.ssss;
        apps.ssss-combine = {
          type = "app";
          program = "${self.packages.${system}.ssss}/bin/ssss-combine";
        };
        apps.ssss-split = {
          type = "app";
          program = "${self.packages.${system}.ssss}/bin/ssss-split";
        };
      });
}
