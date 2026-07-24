//! Integration tests.
//!
//! * Self round-trip: `ssss-split` output combines back to the secret, with and
//!   without `-x`, `-D`, `-w`, and across several `(t,n)` / `-s` values.
//! * Golden vectors: exact share strings captured from the reference C build
//!   (v0.5.7) run against a fixed random source, asserting byte-for-byte
//!   identical generation.
//!
//! Both use the `SSSS_RANDOM_SOURCE` hook to feed a deterministic byte stream:
//! `fixed_random[i] = (i*37 + 11) & 0xff`. The reference vectors were produced
//! by the C `ssss-split` reading that same file, so a match proves the port is
//! byte-for-byte compatible on share generation.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn fixed_random_path() -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push("ssss_rs_fixed_random");
    if !p.exists() {
        let bytes: Vec<u8> = (0..8192u32).map(|i| ((i * 37 + 11) & 0xff) as u8).collect();
        std::fs::write(&p, bytes).unwrap();
    }
    p
}

fn split_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ssss-split"))
}
fn combine_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ssss-combine"))
}

/// Run a binary with the given args, feeding `input` on stdin, returning stdout.
fn run(bin: PathBuf, args: &[&str], input: &str) -> String {
    let mut child = Command::new(bin)
        .args(args)
        .env("SSSS_RANDOM_SOURCE", fixed_random_path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    String::from_utf8(out.stdout).unwrap()
}

fn split(args: &[&str], secret: &str) -> String {
    run(split_bin(), args, &format!("{}\n", secret))
}

fn combine(args: &[&str], shares: &str) -> String {
    run(combine_bin(), args, shares)
}

#[test]
fn golden_share_generation() {
    // (secret, split args, expected exact stdout) captured from C ssss 0.5.7.
    let cases: &[(&str, &[&str], &str)] = &[
        (
            "hello world",
            &["-t", "2", "-n", "3", "-q"],
            "1-89db78eda73e6f147073b5\n2-948b876207735406259b37\n3-9fbbd21898b7bd0816c34b\n",
        ),
        (
            "interop test 42",
            &["-t", "3", "-n", "5", "-q"],
            "1-b31652327bd07c0ef364830026e64e\n2-41732f8f3ace03c082010e1d5499b8\n\
             3-7c18fa506fe5fef7efdadb72616292\n4-c704d85bff196694bbe42c3b2dde8b\n\
             5-fa6f0d84aa329ba3d63ff9541825b3\n",
        ),
        (
            "deadbeef1234",
            &["-t", "3", "-n", "4", "-x", "-q"],
            "1-3c93d8cdf053\n2-6cf5d97bdb4b\n3-8ecbbf59392a\n4-628fde82b6c2\n",
        ),
        (
            "no diffuse",
            &["-t", "2", "-n", "3", "-D", "-q"],
            "1-655f751ef6a28f7b403c\n2-780f8a9156efb46915d1\n3-733fdfebc92b5d672688\n",
        ),
        (
            "tok secret",
            &["-t", "2", "-n", "4", "-w", "mytoken", "-q"],
            "mytoken-1-62222b6e792542dab544\nmytoken-2-7f72d4e1d96879c8e0a9\n\
             mytoken-3-7442819b46ac90c6d3f0\nmytoken-4-45d32bfe99f20fec4b6d\n",
        ),
        (
            // degree % 16 == 8: exercises the diffusion byte fixup
            "abcdef0123456789aa",
            &["-t", "3", "-n", "5", "-x", "-s", "72", "-q"],
            "1-17d79782cc4c7fb18c\n2-330c41d53054ab9059\n3-6041b668438174c5ed\n\
             4-ef8119ab0199617a9f\n5-bcccee16724cbe2f39\n",
        ),
    ];
    for (secret, args, expected) in cases {
        let got = split(args, secret);
        assert_eq!(&got, expected, "golden mismatch for secret {:?}", secret);
    }
}

#[test]
fn self_roundtrip_ascii() {
    for &(t, n) in &[(2u32, 3u32), (3, 5), (5, 9)] {
        let secret = "round trip secret";
        let ts = t.to_string();
        let ns = n.to_string();
        let shares = split(&["-t", &ts, "-n", &ns, "-q"], secret);
        let lines: Vec<&str> = shares.lines().collect();
        // use the first `t` shares
        let subset = lines[..t as usize].join("\n") + "\n";
        let recovered = combine(&["-t", &ts, "-q"], &subset);
        assert_eq!(recovered.trim_end(), secret, "t={} n={}", t, n);
    }
}

#[test]
fn self_roundtrip_hex_and_nodiffusion() {
    let secret = "cafebabedeadbeef";
    // hex mode
    let shares = split(&["-t", "3", "-n", "5", "-x", "-q"], secret);
    let lines: Vec<&str> = shares.lines().collect();
    let subset = format!("{}\n{}\n{}\n", lines[0], lines[2], lines[4]);
    let recovered = combine(&["-t", "3", "-x", "-q"], &subset);
    assert_eq!(recovered.trim_end(), secret);

    // no diffusion
    let shares = split(&["-t", "2", "-n", "3", "-x", "-D", "-q"], secret);
    let lines: Vec<&str> = shares.lines().collect();
    let subset = format!("{}\n{}\n", lines[0], lines[1]);
    let recovered = combine(&["-t", "2", "-x", "-D", "-q"], &subset);
    assert_eq!(recovered.trim_end(), secret);
}

#[test]
fn self_roundtrip_various_security_levels() {
    for &s in &["64", "128", "256", "72", "1024"] {
        let secret = "abcdef01"; // 32 bits of hex
        let shares = split(&["-t", "2", "-n", "3", "-x", "-s", s, "-q"], secret);
        let lines: Vec<&str> = shares.lines().collect();
        let subset = format!("{}\n{}\n", lines[0], lines[1]);
        let recovered = combine(&["-t", "2", "-x", "-q"], &subset);
        // hex output is left-zero-padded to the security level; compare values
        assert_eq!(
            recovered.trim_end().trim_start_matches('0'),
            secret.trim_start_matches('0'),
            "security level {}",
            s
        );
    }
}

/// Run a binary, feeding stdin, returning the exit status (success bool).
fn run_status(bin: PathBuf, args: &[&str], input: &str) -> bool {
    let mut child = Command::new(bin)
        .args(args)
        .env("SSSS_RANDOM_SOURCE", fixed_random_path())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let _ = child.stdin.take().unwrap().write_all(input.as_bytes());
    child.wait().unwrap().success()
}

#[test]
fn duplicate_share_is_inconsistent() {
    // Combining the same share twice must fail (exit 1), not return garbage.
    assert!(
        !run_status(combine_bin(), &["-t", "2", "-q"], "1-abcd1234\n1-abcd1234\n"),
        "duplicate share should fail"
    );
}

#[test]
fn invalid_share_syntax_fails() {
    // No '-' in the share => invalid syntax => exit 1.
    assert!(!run_status(combine_bin(), &["-t", "2", "-q"], "noshare\nalsobad\n"));
}
