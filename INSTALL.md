# Installing

## Prerequisites

1. A system with a proper `/dev/urandom` (the entropy source ssss reads).
2. A Rust toolchain (`cargo` / `rustc`) — any recent stable release. The easiest
  way to get one is [rustup](https://rustup.rs/).
3. Unlike the original C `ssss`, **no C compiler and no `libgmp` are required** —
  the field arithmetic is pure Rust.
4. [xmltoman](http://sourceforge.net/projects/xmltoman/) is optional, and only
  needed to generate the man page. Without it the build still succeeds; only the
  man page is skipped.

## Build & install

Rust's toolchain is cross-platform, so the same steps work on Linux, macOS, and
other Unix-like systems — there is no platform-specific dependency setup.

1. Install Rust (see [rustup.rs](https://rustup.rs/)).
2. Build the release binaries:

    `cargo build --release`

  This produces `target/release/ssss-split` and `target/release/ssss-combine`.

3. Install them onto your `PATH`. Per-user (into `~/.cargo/bin`):

    `cargo install --path .`

  For a system-wide install instead, copy the two binaries to a directory on
  `PATH`, e.g.:

    `sudo install target/release/ssss-split target/release/ssss-combine /usr/local/bin`

The `mlock` feature (memory locking + the `-M` flag) is on by default. To build
the `NOMLOCK` equivalent, add `--no-default-features` to the `cargo` commands
above.

## Man page (optional)

With `xmltoman` installed, generate and view the man page:

```
make doc          # xmltoman ssss.manpage.xml > ssss.1
man ./ssss.1
```

On macOS, `xmltoman` is available via [Homebrew](https://brew.sh/):
`brew install xmltoman`.
