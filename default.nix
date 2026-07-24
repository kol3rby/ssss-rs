{ lib, rustPlatform, installShellFiles, xmltoman }:

# Rust build (rustPlatform.buildRustPackage), replacing the original C + gmp
# derivation. No libgmp: the field arithmetic is pure Rust. Produces the
# ssss-split and ssss-combine binaries and installs the generated man page.
rustPlatform.buildRustPackage {
  pname = "ssss";
  version = "0.5.7";

  src = ./.;

  cargoLock.lockFile = ./Cargo.lock;

  nativeBuildInputs = [ installShellFiles xmltoman ];

  # The test suite spawns the built binaries and exercises terminal/entropy
  # behavior; run it with `cargo test` in development rather than in the
  # sandboxed build.
  doCheck = false;

  # Generate the man page from its xmltoman source (see Makefile /
  # ssss.manpage.xml). Best-effort, mirroring the original Makefile's non-fatal
  # `doc:` target: if xmltoman is unavailable the build still succeeds.
  postBuild = ''
    if xmltoman ssss.manpage.xml > ssss.1.tmp 2>/dev/null && [ -s ssss.1.tmp ]; then
      mv ssss.1.tmp ssss.1
    else
      echo "note: xmltoman unavailable; skipping man page"
      rm -f ssss.1.tmp
    fi
  '';

  postInstall = ''
    if [ -f ssss.1 ]; then installManPage ssss.1; fi
  '';

  meta = with lib; {
    description = "Byte-for-byte compatible Rust port of ssss (Shamir's Secret Sharing Scheme)";
    homepage = "http://point-at-infinity.org/ssss/";
    license = licenses.gpl2Plus;
    platforms = platforms.unix;
    mainProgram = "ssss-split";
  };
}
