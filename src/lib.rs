//! Rust reimplementation of `ssss` v0.5.7 (Shamir's Secret Sharing Scheme),
//! after the original by B. Poettering / J. Frisby.

pub mod cprng;
pub mod ctx;
pub mod diffusion;
pub mod errors;
pub mod field;
pub mod secure;
pub mod shamir;

use ctx::{Ctx, Opts};
use errors::{fatal, save_echo_orig, Error, OPT_QUIET};
use field::field_size_valid;

// `VERSION` is the runtime `-v` banner; it tracks this crate's version (see
// Cargo.toml).
pub const VERSION: &str = "0.5.8";
pub const RANDOM_SOURCE: &str = "/dev/urandom";
pub const MAXDEGREE: i32 = 1024;
pub const MAXTOKENLEN: i32 = 128;
pub const MAXLINELEN: usize = (MAXTOKENLEN as usize) + 1 + 10 + 1 + (MAXDEGREE as usize) / 4 + 10;

/// Parse a leading integer: skip whitespace, an optional sign, then decimal
/// digits (returning 0 when there are none).
pub fn atoi(s: &[u8]) -> i32 {
    let mut i = 0;
    while i < s.len() && matches!(s[i], b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c) {
        i += 1;
    }
    let mut sign: i64 = 1;
    if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
        if s[i] == b'-' {
            sign = -1;
        }
        i += 1;
    }
    let mut val: i64 = 0;
    while i < s.len() && s[i].is_ascii_digit() {
        val = val * 10 + (s[i] - b'0') as i64;
        i += 1;
    }
    (sign * val) as i32
}

#[cfg(feature = "mlock")]
const SPLIT_USAGE: &str = "Split secrets using Shamir's Secret Sharing Scheme.\n\nssss-split -t threshold -n shares [-w token] [-s level] [-M] [-r] [-x] [-q] [-Q] [-D] [-v]\n";
#[cfg(not(feature = "mlock"))]
const SPLIT_USAGE: &str = "Split secrets using Shamir's Secret Sharing Scheme.\n\nssss-split -t threshold -n shares [-w token] [-s level] [-r] [-x] [-q] [-Q] [-D] [-v]\n";

#[cfg(feature = "mlock")]
const COMBINE_USAGE: &str = "Combine shares using Shamir's Secret Sharing Scheme.\n\nssss-combine -t threshold [-M] [-r -n shares] [-x] [-q] [-Q] [-D] [-v]\n";
#[cfg(not(feature = "mlock"))]
const COMBINE_USAGE: &str = "Combine shares using Shamir's Secret Sharing Scheme.\n\nssss-combine -t threshold [-r -n shares] [-x] [-q] [-Q] [-D] [-v]\n";

fn opt_valid(c: char) -> bool {
    if matches!(
        c,
        'v' | 'D' | 'h' | 'q' | 'Q' | 'x' | 'r' | 's' | 't' | 'n' | 'w'
    ) {
        return true;
    }
    cfg!(feature = "mlock") && c == 'M'
}

fn opt_takes_arg(c: char) -> bool {
    matches!(c, 's' | 't' | 'n' | 'w')
}

/// Hand-rolled getopt over the `"MvDhqQxrs:t:n:w:"` option string. Returns
/// `optind`, the index of the first non-option argument.
///
/// Negative `-t`/`-n` values saturate to 0, which the downstream `< Some(2)` /
/// `< threshold` checks then reject. For `-s`, a value of `0` means "unset"
/// (dynamic), while a negative value maps to `Some(0)` so `field_size_valid`
/// still rejects it.
fn parse_opts(opts: &mut Opts, argv: &[String], prog: &str, failed_memory_lock: bool) -> usize {
    let mut optind = 1usize;
    while optind < argv.len() {
        if argv[optind] == "--" {
            optind += 1;
            break;
        }
        let bytes = argv[optind].as_bytes();
        if bytes.len() < 2 || bytes[0] != b'-' {
            break; // first non-option argument
        }
        let chars: Vec<char> = argv[optind][1..].chars().collect();
        let mut ci = 0;
        while ci < chars.len() {
            let c = chars[ci];
            if !opt_valid(c) {
                eprintln!("{}: invalid option -- '{}'", prog, c);
                std::process::exit(1);
            }
            if opt_takes_arg(c) {
                let optarg: String = if ci + 1 < chars.len() {
                    chars[ci + 1..].iter().collect()
                } else {
                    optind += 1;
                    if optind >= argv.len() {
                        eprintln!("{}: option requires an argument -- '{}'", prog, c);
                        std::process::exit(1);
                    }
                    argv[optind].clone()
                };
                match c {
                    's' => {
                        let v = atoi(optarg.as_bytes());
                        opts.security = if v == 0 { None } else { Some(v.max(0) as u32) };
                    }
                    't' => opts.threshold = Some(atoi(optarg.as_bytes()).max(0) as u32),
                    'n' => opts.number = Some(atoi(optarg.as_bytes()).max(0) as u32),
                    'w' => opts.token = Some(optarg),
                    _ => unreachable!(),
                }
                break; // the remainder of this token was the option argument
            } else {
                match c {
                    'v' => opts.show_version = true,
                    'h' => opts.help = true,
                    'q' => opts.quiet = true,
                    'Q' => {
                        opts.very_quiet = true;
                        opts.quiet = true;
                        OPT_QUIET.store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                    'x' => opts.hex = true,
                    'D' => opts.diffusion = false,
                    'r' => opts.recovery = true,
                    'M' => {
                        if failed_memory_lock {
                            fatal("memory lock is required to proceed");
                        }
                    }
                    _ => unreachable!(),
                }
                ci += 1;
            }
        }
        optind += 1;
    }
    optind
}

/// Program entry point. Startup sequence, in order: memory lock, privilege
/// drop, terminal capture, option parsing, then mode dispatch on `argv[0]`.
pub fn run() {
    let argv: Vec<String> = std::env::args().collect();
    let mut opts = Opts::new();

    // 1. Memory locking (unless built without the `mlock` feature).
    #[cfg(feature = "mlock")]
    let failed_memory_lock = {
        let r = unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) };
        if r < 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if e == libc::ENOMEM {
                errors::warning("couldn't get memory lock (ENOMEM, try to adjust RLIMIT_MEMLOCK!)");
            } else if e == libc::EPERM {
                errors::warning("couldn't get memory lock (EPERM, try UID 0!)");
            } else if e == libc::ENOSYS {
                errors::warning(
                    "couldn't get memory lock (ENOSYS, kernel doesn't allow page locking)",
                );
            } else {
                errors::warning("couldn't get memory lock");
            }
            true
        } else {
            false
        }
    };
    #[cfg(not(feature = "mlock"))]
    let failed_memory_lock = false;

    // 2. Secret-bearing buffers zero themselves on Drop (see field::Fe /
    //    secure::secure_zero), so there is no allocator to install here.

    // 3. Privilege drop.
    unsafe {
        if libc::getuid() != libc::geteuid() {
            libc::seteuid(libc::getuid());
        }
    }

    // 4. Capture terminal settings; derive the echo-off variant.
    let mut echo_orig: libc::termios = unsafe { std::mem::zeroed() };
    unsafe {
        libc::tcgetattr(0, &mut echo_orig);
    }
    save_echo_orig(echo_orig);
    let mut echo_off = echo_orig;
    echo_off.c_lflag &= !(libc::ECHO as libc::tcflag_t);

    // 5. help defaults on when invoked with no arguments.
    opts.help = argv.len() == 1;

    // 6. Option parsing.
    let prog = argv.first().cloned().unwrap_or_default();
    let optind = parse_opts(&mut opts, &argv, &prog, failed_memory_lock);

    // 7. Reject trailing non-option arguments.
    if !opts.help && optind != argv.len() {
        fatal("invalid argument");
    }

    // 8. Mode dispatch on the (basename of the) invoked program name.
    let name = match argv[0].rfind('/') {
        Some(p) => &argv[0][p + 1..],
        None => argv[0].as_str(),
    };

    let ec: Result<(), Error> = if name.contains("split") {
        if opts.help || opts.show_version {
            eprint!("{}", SPLIT_USAGE);
            if opts.show_version {
                eprint!("\nVersion: {}", VERSION);
            }
            std::process::exit(0);
        }
        // `None`/`Some(0)`/`Some(1)` all order below `Some(2)`, so unset and
        // out-of-range thresholds are rejected here.
        if opts.threshold < Some(2) {
            fatal("invalid parameters: invalid threshold value");
        }
        if opts.number < opts.threshold {
            fatal("invalid parameters: number of shares smaller than threshold");
        }
        if let Some(s) = opts.security {
            if !field_size_valid(s as i32) {
                fatal("invalid parameters: invalid security level");
            }
        }
        if let Some(tok) = &opts.token {
            if tok.len() > MAXTOKENLEN as usize {
                fatal("invalid parameters: token too long");
            }
        }
        // Splitting in recovery mode is the same as combining with the secret.
        let recovery = opts.recovery;
        let mut ctx = Ctx::new(opts, echo_orig, echo_off);
        if recovery {
            ctx.combine(true)
        } else {
            ctx.split()
        }
    } else {
        if opts.help || opts.show_version {
            eprint!("{}", COMBINE_USAGE);
            if opts.show_version {
                eprint!("\nVersion: {}", VERSION);
            }
            std::process::exit(0);
        }
        if opts.threshold < Some(2) {
            fatal("invalid parameters: invalid threshold value");
        }
        let mut ctx = Ctx::new(opts, echo_orig, echo_off);
        ctx.combine(false)
    };

    if let Err(e) = ec {
        // `fatal_errcode` collapsed into `Display` + this single print site.
        fatal(&e.to_string());
    }
}
