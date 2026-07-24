//! Command-line options, run-state context, and the top-level operations.
//!
//! Configuration and run state are separated: `Opts` is the immutable
//! configuration parsed once from the command line (absent values are `None`
//! rather than sentinels), and `Ctx` is the transient run state — the effective
//! security level derived at runtime, the lazily-built `Field`, and the terminal
//! handles.

use std::io::{Read, Write};

use crate::cprng::Cprng;
use crate::diffusion;
use crate::errors::{warning, Error};
use crate::field::{field_size_valid, Fe, Field};
use crate::secure::secure_zero;
use crate::shamir::{horner_r, restore_secret};
use crate::{MAXDEGREE, MAXLINELEN};

/// Parsed command-line configuration. Set once during arg parsing, then
/// read-only. Absent values are `None` rather than sentinels.
#[derive(Default)]
pub struct Opts {
    pub show_version: bool,
    pub help: bool,
    pub quiet: bool,
    pub very_quiet: bool,
    pub hex: bool,
    pub diffusion: bool,
    pub recovery: bool,
    /// `-s`: the requested security level; `None` selects a dynamic level.
    pub security: Option<u32>,
    /// `-t`: the reconstruction threshold.
    pub threshold: Option<u32>,
    /// `-n`: the number of shares to generate.
    pub number: Option<u32>,
    /// `-w`: an optional token prefix on every share.
    pub token: Option<String>,
}

impl Opts {
    /// Defaults: diffusion on, everything else off/unset.
    pub fn new() -> Opts {
        Opts {
            diffusion: true,
            ..Opts::default()
        }
    }
}

/// Transient run state: the immutable `Opts` plus the effective (possibly
/// runtime-derived) security level, the lazily-initialized field, and the saved
/// terminal modes.
pub struct Ctx {
    pub opts: Opts,
    /// Effective security level: starts at `opts.security` and is filled in by
    /// `ask_secret` when a dynamic level is derived from the secret's length.
    pub security: Option<u32>,
    /// `Some` carries the degree and polynomial; `None` means uninitialized.
    pub field: Option<Field>,
    pub echo_orig: libc::termios,
    pub echo_off: libc::termios,
}

impl Ctx {
    pub fn new(opts: Opts, echo_orig: libc::termios, echo_off: libc::termios) -> Ctx {
        Ctx {
            security: opts.security,
            opts,
            field: None,
            echo_orig,
            echo_off,
        }
    }

    /// The field degree, or 0 when the field is uninitialized.
    pub fn degree(&self) -> u32 {
        self.field.as_ref().map(|f| f.degree).unwrap_or(0)
    }

    fn field(&self) -> &Field {
        self.field.as_ref().expect("field not initialized")
    }

    /// The reconstruction threshold, validated `>= 2` before any operation runs.
    fn threshold(&self) -> usize {
        self.opts.threshold.expect("threshold validated before use") as usize
    }

    /// Build the field once, on first use; later calls are no-ops. The field
    /// lives in `self.field` and drops with the `Ctx`.
    fn ensure_field(&mut self, deg: i32) {
        if self.field.is_none() {
            self.field = Some(Field::new(deg));
        }
    }

    // --- terminal helpers ---

    fn set_echo(&self, t: &libc::termios) {
        unsafe { libc::tcsetattr(0, libc::TCSANOW, t) };
    }

    /// Read one line from stdin: up to MAXLINELEN-1 bytes, stopping after a
    /// newline. Returns `None` only when nothing could be read before EOF.
    fn fgets_line(&self) -> Option<Vec<u8>> {
        let mut out: Vec<u8> = Vec::new();
        let stdin = std::io::stdin();
        let mut lock = stdin.lock();
        let mut byte = [0u8; 1];
        while out.len() < MAXLINELEN - 1 {
            match lock.read(&mut byte) {
                Ok(0) => break,
                Ok(_) => {
                    out.push(byte[0]);
                    if byte[0] == b'\n' {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        if out.is_empty() {
            None
        } else {
            Some(out)
        }
    }

    /// Truncate at the first '\r' or '\n'.
    fn strip_newline(buf: &mut Vec<u8>) {
        if let Some(pos) = buf.iter().position(|&c| c == b'\r' || c == b'\n') {
            buf.truncate(pos);
        }
    }

    /// Prompt for and read the secret, deriving a dynamic security level from
    /// its length when none was requested, then apply the diffusion layer.
    pub fn ask_secret(&mut self) -> Result<Fe, Error> {
        if !self.opts.quiet {
            let deg = self.security.map_or(MAXDEGREE, |s| s as i32);
            eprint!("Enter the secret, ");
            if self.opts.hex {
                eprint!("as most {} hex digits: ", deg / 4);
            } else {
                eprint!("at most {} ASCII characters: ", deg / 8);
            }
        }

        let echo_off = self.echo_off;
        let echo_orig = self.echo_orig;
        self.set_echo(&echo_off);
        let line = self.fgets_line();
        let mut buf = match line {
            Some(b) => b,
            None => return Err(Error::IoReadingSecret),
        };
        // Restore echo and print a newline before parsing.
        self.set_echo(&echo_orig);
        eprintln!();
        Self::strip_newline(&mut buf);

        // Derive a dynamic security level from the secret length when unset.
        if self.security.is_none() {
            let derived = if self.opts.hex {
                4 * ((buf.len() as i32 + 1) & !1)
            } else {
                8 * buf.len() as i32
            };
            if !field_size_valid(derived) {
                secure_zero(&mut buf);
                return Err(Error::InvalidSecurityLevel);
            }
            self.security = Some(derived as u32);
            if !self.opts.quiet {
                eprintln!("Using a {} bit security level.", derived);
            }
        }

        let sec = self.security.expect("security set above") as i32;
        self.ensure_field(sec);
        let hex = self.opts.hex;
        let import = self.field().field_import(&buf, hex);
        let mut secret = match import {
            Ok(s) => s,
            Err(e) => {
                secure_zero(&mut buf);
                return Err(e);
            }
        };

        if self.opts.diffusion {
            if self.degree() >= 64 {
                diffusion::encode(&mut secret, self.degree());
            } else {
                warning("security level too small for the diffusion layer");
            }
        }

        secure_zero(&mut buf);
        Ok(secret)
    }

    /// Evaluate the polynomial at each share index and print the shares.
    pub fn calculate_shares_r(&self, coeff_rev: &[Fe]) {
        let number = self.opts.number.unwrap_or(0);
        let mut fmt_len = 1usize;
        let mut i = number;
        while i >= 10 {
            i /= 10;
            fmt_len += 1;
        }
        let field = self.field();
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        for i in 0..number {
            let x = Fe::from_u32(i + 1);
            let y = horner_r(field, self.threshold(), &x, coeff_rev);
            if let Some(token) = &self.opts.token {
                let _ = write!(out, "{}-", token);
            }
            let _ = write!(out, "{:0width$}-", i + 1, width = fmt_len);
            field.field_print(&mut out, &y, true);
        }
    }

    /// Prompt for and parse one share. Sets `*x` to the parsed index, tracks the
    /// shared security level in `*s`, and returns the share value.
    pub fn ask_share(&mut self, x: &mut Fe, s: &mut u32, i: usize) -> Result<Fe, Error> {
        if !self.opts.quiet {
            eprint!("Share [{}/{}]: ", i + 1, self.threshold());
        }

        let mut buf = match self.fgets_line() {
            Some(b) => b,
            None => return Err(Error::IoReadingShares),
        };
        Self::strip_newline(&mut buf);

        // Parse from the right: last '-' splits the hex value; a second '-'
        // splits the index from an optional token prefix.
        let b_pos = match buf.iter().rposition(|&c| c == b'-') {
            Some(p) => p,
            None => {
                secure_zero(&mut buf);
                return Err(Error::InvalidSyntax);
            }
        };
        let value = buf[b_pos + 1..].to_vec();
        let head = &buf[..b_pos];
        let index_bytes: Vec<u8> = match head.iter().rposition(|&c| c == b'-') {
            Some(a) => head[a + 1..].to_vec(),
            None => head.to_vec(),
        };

        if *s == 0 {
            *s = 4 * value.len() as u32;
            if !field_size_valid(*s as i32) {
                secure_zero(&mut buf);
                return Err(Error::IllegalShareLength);
            }
            self.ensure_field(*s as i32);
        } else if *s != 4 * value.len() as u32 {
            secure_zero(&mut buf);
            return Err(Error::SharesDifferentSecurityLevels);
        }

        let j = crate::atoi(&index_bytes);
        if j == 0 {
            secure_zero(&mut buf);
            return Err(Error::InvalidShare);
        }

        *x = Fe::from_u32(j as u32);
        let import = self.field().field_import(&value, true);
        secure_zero(&mut buf);
        import
    }

    /// Generate the shares: read the secret, draw random coefficients, and
    /// print each share.
    pub fn split(&mut self) -> Result<(), Error> {
        if !self.opts.quiet {
            eprint!(
                "Generating shares using a ({},{}) scheme with ",
                self.opts.threshold.expect("threshold validated"),
                self.opts.number.expect("number validated"),
            );
            match self.security {
                Some(s) => eprint!("a {} bit", s),
                None => eprint!("dynamic"),
            }
            eprintln!(" security level.");
        }

        let t = self.threshold();
        let mut coeff: Vec<Fe> = (0..t).map(|_| Fe::zero()).collect();

        coeff[t - 1] = self.ask_secret()?;

        // `cprng` opens here and closes on drop at the end of the block.
        let mut cprng = Cprng::open()?;
        let degree = self.degree();
        for i in (0..t - 1).rev() {
            coeff[i] = cprng.read(degree)?;
        }
        drop(cprng);

        self.calculate_shares_r(&coeff);
        Ok(())
    }

    /// Reconstruct the secret from shares. With `with_secret`, the secret is
    /// read as the first share to regenerate the remaining shares (recovery).
    pub fn combine(&mut self, with_secret: bool) -> Result<(), Error> {
        let t = self.threshold();
        let mut a: Vec<Vec<Fe>> = (0..t)
            .map(|_| (0..t).map(|_| Fe::zero()).collect())
            .collect();
        let mut y: Vec<Fe> = (0..t).map(|_| Fe::zero()).collect();
        let mut x = Fe::zero();
        let mut s: u32 = 0;

        if !self.opts.quiet {
            eprintln!("Enter {} shares separated by newlines:", self.threshold());
        }

        for i in 0..t {
            if with_secret && i == 0 {
                // For recovering purposes, treat the secret as a share.
                y[i] = self.ask_secret()?;
                s = self.security.expect("security set by ask_secret");
                x = Fe::from_u32(0);
            } else {
                y[i] = self.ask_share(&mut x, &mut s, i)?;
            }

            // Fill the Vandermonde column.
            a[t - 1][i] = Fe::from_u32(1);
            for j in (0..t - 1).rev() {
                a[j][i] = self.field().mul(&a[j + 1][i], &x);
            }
            // Remove the legacy x^k term that horner_r carries.
            x = self.field().mul(&x, &a[0][i]);
            y[i] = &y[i] + &x;
        }

        if restore_secret(self.field(), t, &mut a, &mut y, self.opts.recovery) != 0 {
            return Err(Error::InconsistentShares);
        }

        if !with_secret {
            x = y[t - 1].clone();
            if self.opts.diffusion {
                if self.degree() >= 64 {
                    diffusion::decode(&mut x, self.degree());
                } else {
                    warning("security level too small for the diffusion layer");
                }
            }
            if !self.opts.quiet {
                eprint!("Resulting secret: ");
            }
            let stdout = std::io::stdout();
            let mut out = stdout.lock();
            let hex = self.opts.hex;
            self.field().field_print(&mut out, &x, hex);
        }
        if self.opts.recovery {
            self.calculate_shares_r(&y);
        }
        Ok(())
    }
}
