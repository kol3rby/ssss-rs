//! Rust reimplementation of `ssss` v0.5.7 (Shamir's Secret Sharing Scheme),
//! a faithful, byte-for-byte compatible port of B. Poettering / J. Frisby's
//! `ssss.c`.

pub mod cprng;
pub mod ctx;
pub mod diffusion;
pub mod errors;
pub mod field;
pub mod secure;
pub mod shamir;

use ctx::Ctx;
use errors::{fatal, fatal_errcode, save_echo_orig, SssErrcode, OPT_QUIET};
use field::field_size_valid;

// Top-of-file constants (ssss.c:57-61).
pub const VERSION: &str = "0.5.7";
pub const RANDOM_SOURCE: &str = "/dev/urandom";
pub const MAXDEGREE: i32 = 1024;
pub const MAXTOKENLEN: i32 = 128;
pub const MAXLINELEN: usize =
    (MAXTOKENLEN as usize) + 1 + 10 + 1 + (MAXDEGREE as usize) / 4 + 10;

/// C `atoi`: skip leading whitespace, optional sign, then decimal digits.
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
    if matches!(c, 'v' | 'D' | 'h' | 'q' | 'Q' | 'x' | 'r' | 's' | 't' | 'n' | 'w') {
        return true;
    }
    cfg!(feature = "mlock") && c == 'M'
}

fn opt_takes_arg(c: char) -> bool {
    matches!(c, 's' | 't' | 'n' | 'w')
}

/// Hand-rolled getopt over the exact `"MvDhqQxrs:t:n:w:"` option string, so help
/// text and error behavior match the C build. Returns `optind`.
fn parse_opts(ctx: &mut Ctx, argv: &[String], prog: &str, failed_memory_lock: bool) -> usize {
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
                    's' => ctx.opt_security = atoi(optarg.as_bytes()),
                    't' => ctx.opt_threshold = atoi(optarg.as_bytes()),
                    'n' => ctx.opt_number = atoi(optarg.as_bytes()),
                    'w' => ctx.opt_token = Some(optarg),
                    _ => unreachable!(),
                }
                break; // the remainder of this token was the option argument
            } else {
                match c {
                    'v' => ctx.opt_showversion = true,
                    'h' => ctx.opt_help = true,
                    'q' => ctx.opt_quiet = true,
                    'Q' => {
                        ctx.opt_QUIET = true;
                        ctx.opt_quiet = true;
                        OPT_QUIET.store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                    'x' => ctx.opt_hex = true,
                    'D' => ctx.opt_diffusion = false,
                    'r' => ctx.opt_recovery = true,
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

/// `int main(int argc, char *argv[])` (ssss.c:756). Startup sequence reproduced
/// in order: mlock, secure allocators (n/a under backend A), privilege drop,
/// terminal capture, getopt, mode dispatch on argv[0].
pub fn run() {
    let argv: Vec<String> = std::env::args().collect();
    let mut ctx = Ctx::new();

    // 1. Memory locking (unless built without the `mlock` feature = -DNOMLOCK).
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
                errors::warning("couldn't get memory lock (ENOSYS, kernel doesn't allow page locking)");
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

    // 2. Secure allocators: no GMP allocator to hook under backend (A); field
    //    elements zero on Drop instead (see field::Fe / secure::secure_zero).

    // 3. Privilege drop.
    unsafe {
        if libc::getuid() != libc::geteuid() {
            libc::seteuid(libc::getuid());
        }
    }

    // 4. Capture terminal settings; derive the echo-off variant.
    unsafe {
        libc::tcgetattr(0, &mut ctx.echo_orig);
    }
    save_echo_orig(ctx.echo_orig);
    ctx.echo_off = ctx.echo_orig;
    ctx.echo_off.c_lflag &= !(libc::ECHO as libc::tcflag_t);

    // 5. opt_help defaults to (argc == 1).
    ctx.opt_help = argv.len() == 1;

    // 6. getopt loop.
    let prog = argv.first().cloned().unwrap_or_default();
    let optind = parse_opts(&mut ctx, &argv, &prog, failed_memory_lock);

    // 7. Reject trailing non-option arguments.
    if !ctx.opt_help && optind != argv.len() {
        fatal("invalid argument");
    }

    // 8. Mode dispatch on the (basename of the) invoked program name.
    let name = match argv[0].rfind('/') {
        Some(p) => &argv[0][p + 1..],
        None => argv[0].as_str(),
    };

    let ec: Result<(), SssErrcode> = if name.contains("split") {
        if ctx.opt_help || ctx.opt_showversion {
            eprint!("{}", SPLIT_USAGE);
            if ctx.opt_showversion {
                eprint!("\nVersion: {}", VERSION);
            }
            std::process::exit(0);
        }
        if ctx.opt_threshold < 2 {
            fatal("invalid parameters: invalid threshold value");
        }
        if ctx.opt_number < ctx.opt_threshold {
            fatal("invalid parameters: number of shares smaller than threshold");
        }
        if ctx.opt_security != 0 && !field_size_valid(ctx.opt_security) {
            fatal("invalid parameters: invalid security level");
        }
        if let Some(tok) = &ctx.opt_token {
            if tok.len() > MAXTOKENLEN as usize {
                fatal("invalid parameters: token too long");
            }
        }
        // Splitting in recovery mode is the same as combining with the secret.
        if ctx.opt_recovery {
            ctx.combine(true)
        } else {
            ctx.split()
        }
    } else {
        if ctx.opt_help || ctx.opt_showversion {
            eprint!("{}", COMBINE_USAGE);
            if ctx.opt_showversion {
                eprint!("\nVersion: {}", VERSION);
            }
            std::process::exit(0);
        }
        if ctx.opt_threshold < 2 {
            fatal("invalid parameters: invalid threshold value");
        }
        ctx.combine(false)
    };

    if let Err(e) = ec {
        fatal_errcode(e);
    }
}
