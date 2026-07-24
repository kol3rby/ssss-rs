//! The run-state context and the top-level operations (ssss.c:499-728).
//!
//! The C globals (`opt_*`, `degree`, `poly`, `cprng`, `echo_orig`, `echo_off`)
//! are gathered into a single `Ctx` threaded through the call graph — the main
//! structural concession to Rust. Field names mirror the C globals.

use std::io::{Read, Write};

use crate::cprng::Cprng;
use crate::diffusion::{encode_mpz, EncDec};
use crate::errors::{warning, SssErrcode};
use crate::field::{field_size_valid, Fe, Field};
use crate::secure::secure_zero;
use crate::shamir::{horner_r, restore_secret};
use crate::{MAXDEGREE, MAXLINELEN};

#[allow(non_snake_case)]
pub struct Ctx {
    pub opt_showversion: bool,
    pub opt_help: bool,
    pub opt_quiet: bool,
    pub opt_QUIET: bool,
    pub opt_hex: bool,
    pub opt_diffusion: bool,
    pub opt_security: i32,
    pub opt_threshold: i32,
    pub opt_number: i32,
    pub opt_token: Option<String>,
    pub opt_recovery: bool,

    /// `Some` <-> `degree != 0`; carries `degree` and `poly`.
    pub field: Option<Field>,
    pub cprng: Cprng,
    pub echo_orig: libc::termios,
    pub echo_off: libc::termios,
}

impl Default for Ctx {
    fn default() -> Ctx {
        Ctx::new()
    }
}

impl Ctx {
    pub fn new() -> Ctx {
        Ctx {
            opt_showversion: false,
            opt_help: false,
            opt_quiet: false,
            opt_QUIET: false,
            opt_hex: false,
            opt_diffusion: true, // default 1
            opt_security: 0,
            opt_threshold: -1,
            opt_number: -1,
            opt_token: None,
            opt_recovery: false,
            field: None,
            cprng: Cprng::default(),
            echo_orig: unsafe { std::mem::zeroed() },
            echo_off: unsafe { std::mem::zeroed() },
        }
    }

    /// `degree` global accessor (0 when the field is uninitialized).
    pub fn degree(&self) -> u32 {
        self.field.as_ref().map(|f| f.degree).unwrap_or(0)
    }

    fn field(&self) -> &Field {
        self.field.as_ref().expect("field not initialized")
    }

    /// `void field_init(int deg)` (ssss.c:164) with the `if (!degree)` guard.
    pub fn field_init(&mut self, deg: i32) {
        if self.field.is_none() {
            self.field = Some(Field::init(deg));
        }
    }

    /// `void field_deinit(void)` (ssss.c:178): resets `degree` to 0.
    pub fn field_deinit(&mut self) {
        self.field = None;
    }

    // --- terminal helpers ---

    fn set_echo(&self, t: &libc::termios) {
        unsafe { libc::tcsetattr(0, libc::TCSANOW, t) };
    }

    /// `fgets(buf, sizeof(buf), stdin)` semantics over the shared, buffered
    /// stdin: read up to MAXLINELEN-1 bytes, stopping after a newline. Returns
    /// `None` only when nothing could be read before EOF (fgets -> NULL).
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

    /// Truncate at the first '\r' or '\n' (`buf[strcspn(buf, "\r\n")] = '\0'`).
    fn strip_newline(buf: &mut Vec<u8>) {
        if let Some(pos) = buf.iter().position(|&c| c == b'\r' || c == b'\n') {
            buf.truncate(pos);
        }
    }

    /// `enum ssss_errcode ask_secret(mpz_t secret)` (ssss.c:499).
    pub fn ask_secret(&mut self) -> Result<Fe, SssErrcode> {
        if !self.opt_quiet {
            let deg = if self.opt_security != 0 {
                self.opt_security
            } else {
                MAXDEGREE
            };
            eprint!("Enter the secret, ");
            if self.opt_hex {
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
            None => return Err(SssErrcode::IoReadingSecret),
        };
        // On success the C restores echo and prints a newline before parsing.
        self.set_echo(&echo_orig);
        eprintln!();
        Self::strip_newline(&mut buf);

        if self.opt_security == 0 {
            self.opt_security = if self.opt_hex {
                4 * ((buf.len() as i32 + 1) & !1)
            } else {
                8 * buf.len() as i32
            };
            if !field_size_valid(self.opt_security) {
                secure_zero(&mut buf);
                return Err(SssErrcode::InvalidSecurityLevel);
            }
            if !self.opt_quiet {
                eprintln!("Using a {} bit security level.", self.opt_security);
            }
        }

        self.field_init(self.opt_security);
        let hex = self.opt_hex;
        let import = self.field().field_import(&buf, hex);
        let mut secret = match import {
            Ok(s) => s,
            Err(e) => {
                secure_zero(&mut buf);
                return Err(e);
            }
        };

        if self.opt_diffusion {
            if self.degree() >= 64 {
                encode_mpz(&mut secret, self.degree(), EncDec::Encode);
            } else {
                warning("security level too small for the diffusion layer");
            }
        }

        secure_zero(&mut buf);
        Ok(secret)
    }

    /// `void calculate_shares_r(const mpz_t coeff_rev[])` (ssss.c:592).
    pub fn calculate_shares_r(&self, coeff_rev: &[Fe]) {
        let mut fmt_len = 1usize;
        let mut i = self.opt_number;
        while i >= 10 {
            i /= 10;
            fmt_len += 1;
        }
        let field = self.field();
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        for i in 0..self.opt_number {
            let x = Fe::from_u32((i + 1) as u32);
            let y = horner_r(field, self.opt_threshold as usize, &x, coeff_rev);
            if let Some(token) = &self.opt_token {
                let _ = write!(out, "{}-", token);
            }
            let _ = write!(out, "{:0width$}-", i + 1, width = fmt_len);
            field.field_print(&mut out, &y, true);
        }
    }

    /// `enum ssss_errcode ask_share(mpz_t x, mpz_t share, unsigned *s, int i)`
    /// (ssss.c:615). Sets `*x` to the parsed index and returns the share.
    pub fn ask_share(&mut self, x: &mut Fe, s: &mut u32, i: usize) -> Result<Fe, SssErrcode> {
        if !self.opt_quiet {
            eprint!("Share [{}/{}]: ", i + 1, self.opt_threshold);
        }

        let mut buf = match self.fgets_line() {
            Some(b) => b,
            None => return Err(SssErrcode::IoReadingShares),
        };
        Self::strip_newline(&mut buf);

        // Parse from the right: last '-' splits the hex value; a second '-'
        // splits the index from an optional token prefix.
        let b_pos = match buf.iter().rposition(|&c| c == b'-') {
            Some(p) => p,
            None => {
                secure_zero(&mut buf);
                return Err(SssErrcode::InvalidSyntax);
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
                return Err(SssErrcode::IllegalShareLength);
            }
            self.field_init(*s as i32);
        } else if *s != 4 * value.len() as u32 {
            secure_zero(&mut buf);
            return Err(SssErrcode::SharesDifferentSecurityLevels);
        }

        let j = crate::atoi(&index_bytes);
        if j == 0 {
            secure_zero(&mut buf);
            return Err(SssErrcode::InvalidShare);
        }

        *x = Fe::from_u32(j as u32);
        let import = self.field().field_import(&value, true);
        secure_zero(&mut buf);
        import
    }

    /// `enum ssss_errcode split(void)` (ssss.c:553).
    pub fn split(&mut self) -> Result<(), SssErrcode> {
        let r = self.split_inner();
        self.field_deinit();
        r
    }

    fn split_inner(&mut self) -> Result<(), SssErrcode> {
        if !self.opt_quiet {
            eprint!(
                "Generating shares using a ({},{}) scheme with ",
                self.opt_threshold, self.opt_number
            );
            if self.opt_security != 0 {
                eprint!("a {} bit", self.opt_security);
            } else {
                eprint!("dynamic");
            }
            eprintln!(" security level.");
        }

        let t = self.opt_threshold as usize;
        let mut coeff: Vec<Fe> = (0..t).map(|_| Fe::zero()).collect();

        coeff[t - 1] = self.ask_secret()?;

        self.cprng.cprng_init()?;
        let degree = self.degree();
        for i in (0..t - 1).rev() {
            match self.cprng.cprng_read(degree) {
                Ok(v) => coeff[i] = v,
                Err(e) => {
                    return Err(e);
                }
            }
        }
        self.cprng.cprng_deinit()?;

        self.calculate_shares_r(&coeff);
        Ok(())
    }

    /// `enum ssss_errcode combine(int with_secret)` (ssss.c:666).
    pub fn combine(&mut self, with_secret: bool) -> Result<(), SssErrcode> {
        let r = self.combine_inner(with_secret);
        self.field_deinit();
        r
    }

    fn combine_inner(&mut self, with_secret: bool) -> Result<(), SssErrcode> {
        let t = self.opt_threshold as usize;
        let mut a: Vec<Vec<Fe>> = (0..t).map(|_| (0..t).map(|_| Fe::zero()).collect()).collect();
        let mut y: Vec<Fe> = (0..t).map(|_| Fe::zero()).collect();
        let mut x = Fe::zero();
        let mut s: u32 = 0;

        if !self.opt_quiet {
            eprintln!("Enter {} shares separated by newlines:", self.opt_threshold);
        }

        for i in 0..t {
            if with_secret && i == 0 {
                // For recovering purposes, treat the secret as a share.
                y[i] = self.ask_secret()?;
                s = self.opt_security as u32;
                x = Fe::from_u32(0);
            } else {
                y[i] = self.ask_share(&mut x, &mut s, i)?;
            }

            // Fill the Vandermonde column.
            a[t - 1][i] = Fe::from_u32(1);
            for j in (0..t - 1).rev() {
                a[j][i] = self.field().field_mult(&a[j + 1][i], &x);
            }
            // Remove the legacy x^k term (see comment at top of horner()).
            x = self.field().field_mult(&x, &a[0][i]);
            y[i] = Fe::xor(&y[i], &x);
        }

        if restore_secret(self.field(), t, &mut a, &mut y, self.opt_recovery) != 0 {
            return Err(SssErrcode::InconsistentShares);
        }

        if !with_secret {
            x = y[t - 1].clone();
            if self.opt_diffusion {
                if self.degree() >= 64 {
                    encode_mpz(&mut x, self.degree(), EncDec::Decode);
                } else {
                    warning("security level too small for the diffusion layer");
                }
            }
            if !self.opt_quiet {
                eprint!("Resulting secret: ");
            }
            let stdout = std::io::stdout();
            let mut out = stdout.lock();
            let hex = self.opt_hex;
            self.field().field_print(&mut out, &x, hex);
        }
        if self.opt_recovery {
            self.calculate_shares_r(&y);
        }
        Ok(())
    }
}
