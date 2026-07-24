//! The `Error` type and the emergency abort / warning helpers.
//!
//! One `Error` type carries both identity and message: the variants are the
//! failure kinds, and their strings live in the `Display` impl. Aborting funnels
//! through the single `fatal` print site in `run()`. Success is `Ok(())`, and
//! every reachable failure has its own variant.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

/// Whether `-Q` was given; `warning()` stays silent when set (set once during
/// arg parse).
pub static OPT_QUIET: AtomicBool = AtomicBool::new(false);

/// Original terminal settings, saved at startup and restored by `fatal`.
static ECHO_ORIG: OnceLock<libc::termios> = OnceLock::new();

pub fn save_echo_orig(t: libc::termios) {
    let _ = ECHO_ORIG.set(t);
}

/// A recoverable failure. The `Display` messages are the exact strings printed
/// by `fatal`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
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
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            Error::InputStringTooLong => "input string too long",
            Error::InvalidSyntax => "invalid syntax",
            Error::OpenRandom => "couldn't open /dev/urandom",
            Error::CloseRandom => "couldn't close /dev/urandom",
            Error::ReadRandom => "couldn't read from /dev/urandom",
            Error::IoReadingSecret => "I/O error while reading secret",
            Error::InvalidSecurityLevel => "security level invalid (secret too long?)",
            Error::IoReadingShares => "I/O error while reading shares",
            Error::IllegalShareLength => "share has illegal length",
            Error::SharesDifferentSecurityLevels => "shares have different security levels",
            Error::InvalidShare => "invalid share",
            Error::InconsistentShares => {
                "shares inconsistent. Perhaps a single share was used twice"
            }
        };
        f.write_str(msg)
    }
}

impl std::error::Error for Error {}

/// Crate-wide `Result` alias.
pub type Result<T> = std::result::Result<T, Error>;

fn isatty(fd: i32) -> bool {
    unsafe { libc::isatty(fd) != 0 }
}

/// Restore the terminal, ring the tty bell on stderr, and `exit(1)`. The sole
/// print-and-exit edge: both the startup parameter checks and a failed `Error`
/// (via its `Display`) funnel through here.
pub fn fatal(msg: &str) -> ! {
    if let Some(t) = ECHO_ORIG.get() {
        unsafe { libc::tcsetattr(0, libc::TCSANOW, t) };
    }
    eprintln!("{}FATAL: {}.", if isatty(2) { "\x07" } else { "" }, msg);
    std::process::exit(1);
}

/// Print a warning to stderr, suppressed when `-Q` was given.
pub fn warning(msg: &str) {
    if !OPT_QUIET.load(Ordering::Relaxed) {
        eprintln!("{}WARNING: {}.", if isatty(2) { "\x07" } else { "" }, msg);
    }
}
