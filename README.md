# ssss-rs

Shamir's Secret Sharing Scheme.

## Rust port

This is a Rust reimplementation of B. Poettering / J. Frisby's
[SSSS](https://github.com/MrJoy/ssss) ("Shamir's Secret Sharing Scheme"). It is a
faithful, byte-for-byte compatible port of the original C `ssss.c`: shares are
interchangeable with the C tool in both directions, and — given the same secret
and random stream — the two produce identical shares. Unlike the original there
is no `libgmp` dependency; the field arithmetic is pure Rust.

## Run using Nix

```sh
# ssss-split
nix run 'github:kol3rby/ssss-rs#ssss-split'

# ssss-combine
nix run 'github:kol3rby/ssss-rs#ssss-combine'
```

## What You Need To Know

Please read B. Poettering's page on SSSS before proceeding. SSSS, like all
cryptographic algorithms, can lead to a false sense of security if improperly
used. Be sure you understand the role it serves, and the limitations it has
before employing it.

[http://point-at-infinity.org/ssss/index.html](http://point-at-infinity.org/ssss/index.html)

## Version

This port is based on SSSS v0.5.7.

## Verification and Installation (VERY IMPORTANT!)

Before installing, when cloning this repo, use a signed tag and verify the
signature first!

```bash
# First, make sure you have the signing key in your GPG keychain:
gpg --keyserver keys.openpgp.org --recv-keys 0AEC8C5B

# Now, clone the repo and verify the release tag:
git clone https://github.com/kol3rby/ssss-rs.git
cd ssss-rs
git tag -v v0.5.7

# You should see output to the effect of:
#   gpg: Signature made <date and time> using RSA key ID 0AEC8C5B
#   gpg: Good signature from "kol3rby <kol3rby@riseup.net>" [key 0AEC8C5B]
#
# If you do NOT see a 'Good signature' from key ID 0AEC8C5B, do NOT proceed
# with installation!
#
git checkout v0.5.7 # This will put you in 'detached HEAD' mode, which is fine
                    # but don't make changes as you are no longer on a branch!
# Proceed with the build steps from here. See INSTALL.md for details.
```

## License

This port follows the same license as the original software: The GPLv2. See
LICENSE for more information.
