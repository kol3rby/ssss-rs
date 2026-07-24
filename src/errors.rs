//! Error codes and the emergency abort / warning helpers (ssss.c:95-152).
//!
//! `enum ssss_errcode` and `ssss_errmsg[]` are ported directly. Interior
//! functions return `Result<_, SssErrcode>` (Ok(()) <-> ssss_ec_ok); `fatal` /
//! `fatal_errcode` / `warning` are the print-and-exit edges.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

/// Mirrors the `opt_QUIET` global for `warning()` (set once during arg parse).
pub static OPT_QUIET: AtomicBool = AtomicBool::new(false);

/// Original terminal settings, saved by `main`, restored by `fatal`.
/// Replaces the `struct termios echo_orig` global.
static ECHO_ORIG: OnceLock<libc::termios> = OnceLock::new();

pub fn save_echo_orig(t: libc::termios) {
    let _ = ECHO_ORIG.set(t);
}

/// `enum ssss_errcode` (ssss.c:95-110). Discriminants match the C ordering so
/// they index `SSSS_ERRMSG` identically. `Ok` <-> `ssss_ec_ok`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(i32)]
pub enum SssErrcode {
    Ok = 0,
    InputStringTooLong,
    InvalidSyntax,
    OpenRandom,
    CloseRandom,
    ReadRandom,
    IoReadingSecret,
    InvalidSecurityLevel,
    IoReadingShares,
    IllegalShareLength,
    SharesDifferentSecurityLevels,
    InvalidShare,
    InconsistentShares,
    Unknown,
}

/// `ssss_errmsg[]` (ssss.c:112-127). Kept byte-identical so `fatal_errcode`
/// output matches. `RANDOM_SOURCE` is spelled out (the C used string pasting).
pub const SSSS_ERRMSG: [&str; 14] = [
    "ok",
    "input string too long",
    "invalid syntax",
    "couldn't open /dev/urandom",
    "couldn't close /dev/urandom",
    "couldn't read from /dev/urandom",
    "I/O error while reading secret",
    "security level invalid (secret too long?)",
    "I/O error while reading shares",
    "share has illegal length",
    "shares have different security levels",
    "invalid share",
    "shares inconsistent. Perhaps a single share was used twice",
    "unknown error",
];

fn isatty(fd: i32) -> bool {
    unsafe { libc::isatty(fd) != 0 }
}

/// `void fatal(const char *msg)` (ssss.c:136). Restores the terminal, rings the
/// tty bell on stderr, and exits(1).
pub fn fatal(msg: &str) -> ! {
    if let Some(t) = ECHO_ORIG.get() {
        unsafe { libc::tcsetattr(0, libc::TCSANOW, t) };
    }
    eprintln!("{}FATAL: {}.", if isatty(2) { "\x07" } else { "" }, msg);
    std::process::exit(1);
}

/// `void fatal_errcode(enum ssss_errcode ec)` (ssss.c:143).
pub fn fatal_errcode(ec: SssErrcode) -> ! {
    let i = ec as i32;
    let idx = if i > SssErrcode::Ok as i32 && i < SssErrcode::Unknown as i32 {
        i as usize
    } else {
        SssErrcode::Unknown as usize
    };
    fatal(SSSS_ERRMSG[idx]);
}

/// `void warning(char *msg)` (ssss.c:148). Suppressed under `opt_QUIET`.
pub fn warning(msg: &str) {
    if !OPT_QUIET.load(Ordering::Relaxed) {
        eprintln!("{}WARNING: {}.", if isatty(2) { "\x07" } else { "" }, msg);
    }
}
