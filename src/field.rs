//! GF(2^deg) field arithmetic and field-element I/O (ssss.c:154-296).
//!
//! Backend (A): a field element (`Fe`) is an arbitrary-precision non-negative
//! integer stored as little-endian bytes (`b[0]` = least significant byte).
//! Every operation the C code performs via GMP `mpz_*` is reproduced here with
//! identical bit-level semantics. In particular `Fe::export` / `Fe::import`
//! mirror the `order` / `size` / `endian` arguments of `mpz_export` /
//! `mpz_import` so the several different layouts the C uses line up exactly.
//!
//! Naming: pure destination-arg free functions in C (`field_add(z,x,y)`) become
//! value-returning functions/methods here — the language forbids the aliasing
//! the out-parameter form relied on. Names are preserved; the `assert(z != y)`
//! aliasing contract of `field_mult` is made unrepresentable by the API.

use crate::errors::{warning, SssErrcode};
use crate::secure::secure_zero;
use std::io::Write;

/// Coefficients of some irreducible polynomials over GF(2) (ssss.c:64-76).
/// Copied verbatim: three coefficients per degree, for degrees 8, 16, ... 1024.
#[rustfmt::skip]
pub(crate) static IRRED_COEFF: &[u8] = &[
    4,3,1,5,3,1,4,3,1,7,3,2,5,4,3,5,3,2,7,4,2,4,3,1,10,9,3,9,4,2,7,6,2,10,9,
    6,4,3,1,5,4,3,4,3,1,7,2,1,5,3,2,7,4,2,6,3,2,5,3,2,15,3,2,11,3,2,9,8,7,7,
    2,1,5,3,2,9,3,1,7,3,1,9,8,3,9,4,2,8,5,3,15,14,10,10,5,2,9,6,2,9,3,2,9,5,
    2,11,10,1,7,3,2,11,2,1,9,7,4,4,3,1,8,3,1,7,4,1,7,2,1,13,11,6,5,3,2,7,3,2,
    8,7,5,12,3,2,13,10,6,5,3,2,5,3,2,9,5,2,9,7,2,13,4,3,4,3,1,11,6,4,18,9,6,
    19,18,13,11,3,2,15,9,6,4,3,1,16,5,2,15,14,6,8,5,2,15,11,2,11,6,2,7,5,3,8,
    3,1,19,16,9,11,9,6,15,7,6,13,4,3,14,13,3,13,6,3,9,5,2,19,13,6,19,10,3,11,
    6,5,9,2,1,14,3,2,13,3,1,7,5,4,11,9,8,11,6,5,23,16,9,19,14,6,23,10,2,8,3,
    2,5,4,3,9,6,4,4,3,2,13,8,6,13,11,1,13,10,3,11,6,5,19,17,4,15,14,7,13,9,6,
    9,7,3,9,7,1,14,3,2,11,8,2,11,6,4,13,5,2,11,5,1,11,4,1,19,10,3,21,10,6,13,
    3,1,15,7,5,19,18,10,7,5,3,12,7,2,7,5,1,14,9,6,10,3,2,15,13,12,12,11,9,16,
    9,7,12,9,3,9,5,2,17,10,6,24,9,3,17,15,13,5,4,3,19,17,8,15,6,3,19,6,1 ];

/// `int field_size_valid(int deg)` (ssss.c:156).
pub fn field_size_valid(deg: i32) -> bool {
    (8..=crate::MAXDEGREE).contains(&deg) && deg % 8 == 0
}

/// A GF(2^deg) field element: a non-negative bignum in little-endian bytes.
/// Zeroed on `Drop` (the RAII replacement for GMP's `secure_free`/`secure_realloc`).
#[derive(Clone, Default)]
pub struct Fe {
    b: Vec<u8>,
}

impl PartialEq for Fe {
    // Compare by numeric value: trailing zero bytes are not significant, so
    // `[0x12]` and `[0x12, 0x00]` (the same integer) must compare equal.
    fn eq(&self, other: &Fe) -> bool {
        let n = self.b.len().max(other.b.len());
        (0..n).all(|i| {
            self.b.get(i).copied().unwrap_or(0) == other.b.get(i).copied().unwrap_or(0)
        })
    }
}
impl Eq for Fe {}

impl Drop for Fe {
    fn drop(&mut self) {
        secure_zero(&mut self.b);
    }
}

impl std::fmt::Debug for Fe {
    // Used only by test assertions; the binary never prints an `Fe` via Debug.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Fe(0x{})", self.to_hex())
    }
}

impl Fe {
    /// The additive identity (mpz value 0).
    pub fn zero() -> Fe {
        Fe { b: Vec::new() }
    }

    /// `mpz_set_ui` for small values (used with 0, 1, and share indices).
    pub fn from_u32(v: u32) -> Fe {
        Fe {
            b: v.to_le_bytes().to_vec(),
        }
    }

    /// `mpz_cmp_ui(x, 0) == 0`.
    pub fn is_zero(&self) -> bool {
        self.b.iter().all(|&x| x == 0)
    }

    /// True iff the value is exactly 1 (`mpz_cmp_ui(x, 1) == 0`).
    pub fn is_one(&self) -> bool {
        self.b.first() == Some(&1) && self.b.iter().skip(1).all(|&x| x == 0)
    }

    /// `mpz_tstbit(x, i)`.
    pub fn bit(&self, i: usize) -> bool {
        let by = i / 8;
        by < self.b.len() && (self.b[by] >> (i % 8)) & 1 == 1
    }

    /// `mpz_setbit(x, i)`.
    pub fn setbit(&mut self, i: usize) {
        let by = i / 8;
        if by >= self.b.len() {
            self.b.resize(by + 1, 0);
        }
        self.b[by] |= 1 << (i % 8);
    }

    /// `mpz_sizeinbits`-style bit length: 0 for zero, else index of the highest
    /// set bit plus one (equal to `mpz_sizeinbase(x, 2)` for nonzero x).
    pub fn bits(&self) -> usize {
        for by in (0..self.b.len()).rev() {
            let v = self.b[by];
            if v != 0 {
                return by * 8 + (8 - v.leading_zeros() as usize);
            }
        }
        0
    }

    /// `mpz_sizeinbase(x, 16)`: number of hex digits. GMP returns 1 for zero.
    pub fn sizeinbase16(&self) -> usize {
        let bits = self.bits();
        if bits == 0 {
            1
        } else {
            bits.div_ceil(4)
        }
    }

    /// `mpz_xor(z, x, y)` — this field's `field_add` and `field_sub`.
    pub fn xor(x: &Fe, y: &Fe) -> Fe {
        let n = x.b.len().max(y.b.len());
        let mut b = vec![0u8; n];
        for (i, out) in b.iter_mut().enumerate() {
            let xb = x.b.get(i).copied().unwrap_or(0);
            let yb = y.b.get(i).copied().unwrap_or(0);
            *out = xb ^ yb;
        }
        Fe { b }
    }

    /// Left shift by `l` bits, i.e. multiply by 2^l (`mpz_mul_2exp`, the
    /// `mpz_lshift` macro at ssss.c:131).
    pub fn shl(&self, l: usize) -> Fe {
        if self.is_zero() {
            return Fe::zero();
        }
        let byte_shift = l / 8;
        let bit_shift = l % 8;
        let mut b = vec![0u8; self.b.len() + byte_shift + 1];
        for (i, &src) in self.b.iter().enumerate() {
            let v = (src as u16) << bit_shift;
            b[i + byte_shift] |= v as u8;
            b[i + byte_shift + 1] |= (v >> 8) as u8;
        }
        Fe { b }
    }

    /// Parse a hex string big-endian (`mpz_set_str(x, s, 16)`), returning an
    /// error on any non-hex byte or on an empty string (both `-1` in GMP).
    // The unit error mirrors GMP's `-1` sentinel; the caller maps it to the
    // appropriate `SssErrcode`.
    #[allow(clippy::result_unit_err)]
    pub fn from_hex(s: &[u8]) -> Result<Fe, ()> {
        if s.is_empty() {
            return Err(());
        }
        let mut b: Vec<u8> = Vec::new();
        // Walk from least significant nibble (rightmost char).
        for (nibble_index, &ch) in s.iter().rev().enumerate() {
            let d = match (ch as char).to_digit(16) {
                Some(d) => d as u8,
                None => return Err(()),
            };
            let byte_i = nibble_index / 2;
            if byte_i >= b.len() {
                b.push(0);
            }
            if nibble_index % 2 == 0 {
                b[byte_i] |= d;
            } else {
                b[byte_i] |= d << 4;
            }
        }
        Ok(Fe { b })
    }

    /// `mpz_out_str(stream, 16, x)`: lowercase hex, no leading zeros, "0" for 0.
    pub fn to_hex(&self) -> String {
        if self.is_zero() {
            return "0".to_string();
        }
        let ndigits = self.sizeinbase16();
        let mut s = String::with_capacity(ndigits);
        for d in (0..ndigits).rev() {
            let byte = self.b[d / 2];
            let nib = if d % 2 == 0 { byte & 0x0f } else { byte >> 4 };
            s.push(std::char::from_digit(nib as u32, 16).unwrap());
        }
        s
    }

    /// Reproduce `mpz_export(out, &count, order, size, endian, 0, x)`.
    ///
    /// * `order`  ==  1: most-significant word first; == -1: least first.
    /// * `size`:  bytes per word.
    /// * `endian` ==  1: big-endian bytes within a word; <= 0: little/native.
    ///
    /// Returns the byte buffer (length `count*size`, no leading zero words) and
    /// the word count.
    pub fn export(&self, order: i32, size: usize, endian: i32) -> (Vec<u8>, usize) {
        let bits = self.bits();
        let wordbits = size * 8;
        let nwords = if bits == 0 { 0 } else { bits.div_ceil(wordbits) };
        let mut le = self.b.clone();
        le.resize(nwords * size, 0);
        let mut out = vec![0u8; nwords * size];
        for w in 0..nwords {
            let slot = if order >= 0 { nwords - 1 - w } else { w };
            for k in 0..size {
                let byteval = le[w * size + k];
                let pos = if endian > 0 {
                    slot * size + (size - 1 - k)
                } else {
                    slot * size + k
                };
                out[pos] = byteval;
            }
        }
        (out, nwords)
    }

    /// Reproduce `mpz_import(x, count, order, size, endian, 0, buf)` — the
    /// inverse of `export` with the same argument meanings.
    pub fn import(buf: &[u8], count: usize, order: i32, size: usize, endian: i32) -> Fe {
        let mut le = vec![0u8; count * size];
        for slot in 0..count {
            let w = if order >= 0 { count - 1 - slot } else { slot };
            for k in 0..size {
                let pos = if endian > 0 {
                    slot * size + (size - 1 - k)
                } else {
                    slot * size + k
                };
                le[w * size + k] = buf[pos];
            }
        }
        Fe { b: le }
    }
}

/// A field context: the degree and the irreducible polynomial `poly`.
/// Replaces the C globals `unsigned int degree` and `mpz_t poly`. A `None`
/// `Ctx.field` corresponds to `degree == 0` (the "uninitialized" sentinel).
pub struct Field {
    pub degree: u32,
    pub poly: Fe,
}

impl Field {
    /// `void field_init(int deg)` (ssss.c:164). The `if (!degree)` guard is
    /// enforced by the caller (`Ctx::field_init`) — it only builds a new
    /// `Field` when none exists yet.
    pub fn init(deg: i32) -> Field {
        assert!(field_size_valid(deg));
        let mut poly = Fe::zero();
        poly.setbit(deg as usize);
        let base = 3 * (deg as usize / 8 - 1);
        poly.setbit(IRRED_COEFF[base] as usize);
        poly.setbit(IRRED_COEFF[base + 1] as usize);
        poly.setbit(IRRED_COEFF[base + 2] as usize);
        poly.setbit(0);
        Field {
            degree: deg as u32,
            poly,
        }
    }

    /// `void field_mult(mpz_t z, x, y)` (ssss.c:253). Carry-less multiply mod
    /// `poly`. Returns z; the C `assert(z != y)` contract is structural here.
    pub fn field_mult(&self, x: &Fe, y: &Fe) -> Fe {
        let mut b = x.clone();
        let mut z = if y.bit(0) { x.clone() } else { Fe::zero() };
        let deg = self.degree as usize;
        for i in 1..deg {
            b = b.shl(1);
            if b.bit(deg) {
                b = Fe::xor(&b, &self.poly);
            }
            if y.bit(i) {
                z = Fe::xor(&z, &b);
            }
        }
        z
    }

    /// `void field_invert(mpz_t z, x)` (ssss.c:273). Almost-inverse loop over
    /// GF(2^deg). Asserts x != 0, as the C does.
    pub fn field_invert(&self, x: &Fe) -> Fe {
        assert!(!x.is_zero());
        let mut u = x.clone();
        let mut v = self.poly.clone();
        let mut g = Fe::zero();
        let mut z = Fe::from_u32(1);
        while !u.is_one() {
            let mut i = u.bits() as i64 - v.bits() as i64;
            if i < 0 {
                std::mem::swap(&mut u, &mut v);
                std::mem::swap(&mut z, &mut g);
                i = -i;
            }
            let h = v.shl(i as usize);
            u = Fe::xor(&u, &h);
            let h = g.shl(i as usize);
            z = Fe::xor(&z, &h);
        }
        z
    }

    /// `enum ssss_errcode field_import(mpz_t x, const char *s, int hexmode)`
    /// (ssss.c:187). Returns the imported element or an error code. `s` is the
    /// raw input bytes (so binary ASCII secrets round-trip like the C `char*`).
    pub fn field_import(&self, s: &[u8], hexmode: bool) -> Result<Fe, SssErrcode> {
        let deg = self.degree as usize;
        if hexmode {
            if s.len() > deg / 4 {
                return Err(SssErrcode::InputStringTooLong);
            }
            if s.len() < deg / 4 {
                warning("input string too short, adding null padding on the left");
            }
            Fe::from_hex(s).map_err(|_| SssErrcode::InvalidSyntax)
        } else {
            if s.len() > deg / 8 {
                return Err(SssErrcode::InputStringTooLong);
            }
            let warn = s.iter().any(|&c| !(32..127).contains(&c));
            if warn {
                warning("binary data detected, use -x mode instead");
            }
            Ok(Fe::import(s, s.len(), 1, 1, 0))
        }
    }

    /// `void field_print(FILE *stream, const mpz_t x, int hexmode)`
    /// (ssss.c:216).
    pub fn field_print<W: Write>(&self, stream: &mut W, x: &Fe, hexmode: bool) {
        let deg = self.degree as usize;
        if hexmode {
            let pad = (deg / 4).saturating_sub(x.sizeinbase16());
            for _ in 0..pad {
                let _ = write!(stream, "0");
            }
            let _ = write!(stream, "{}", x.to_hex());
            let _ = writeln!(stream);
        } else {
            // order=1, size=1: big-endian bytes, leading zero bytes dropped.
            let (mut buf, t) = x.export(1, 1, 0);
            let mut warn = false;
            for &byte in buf.iter().take(t) {
                let printable = (32..127).contains(&byte);
                warn |= !printable;
                let _ = write!(stream, "{}", if printable { byte as char } else { '.' });
            }
            let _ = writeln!(stream);
            if warn {
                warning("binary data detected, use -x mode instead");
            }
            secure_zero(&mut buf);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_validity() {
        assert!(field_size_valid(8));
        assert!(field_size_valid(64));
        assert!(field_size_valid(1024));
        assert!(!field_size_valid(0));
        assert!(!field_size_valid(7));
        assert!(!field_size_valid(1032));
        assert!(!field_size_valid(40 + 1));
    }

    #[test]
    fn hex_roundtrip() {
        // to_hex() emits no leading zeros, so use inputs without any.
        for s in ["1", "ff", "deadbeef", "123456789abcdef", "a", "100"] {
            let x = Fe::from_hex(s.as_bytes()).unwrap();
            assert_eq!(x.to_hex(), s);
        }
        // Leading zeros in the input are dropped on the way back out.
        assert_eq!(Fe::from_hex(b"00ff").unwrap().to_hex(), "ff");
        assert_eq!(Fe::zero().to_hex(), "0");
        assert!(Fe::from_hex(b"").is_err());
        assert!(Fe::from_hex(b"xyz").is_err());
    }

    #[test]
    fn shift_and_bits() {
        let one = Fe::from_u32(1);
        assert_eq!(one.bits(), 1);
        assert_eq!(one.shl(10).bits(), 11);
        assert!(one.shl(10).bit(10));
        assert!(!one.shl(10).bit(9));
        assert_eq!(Fe::zero().bits(), 0);
    }

    // x * x^{-1} == 1 for many random x, at several degrees.
    #[test]
    fn inverse_roundtrip() {
        let mut state: u64 = 0x1234_5678_9abc_def0;
        let mut rng = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for &deg in &[8i32, 64, 128, 256, 1024] {
            let field = Field::init(deg);
            for _ in 0..64 {
                // build a random nonzero element with < deg bits
                let mut x = Fe::zero();
                let bytes = (deg / 8) as usize;
                for by in 0..bytes {
                    let r = (rng() & 0xff) as u8;
                    if r != 0 {
                        for bit in 0..8 {
                            if r >> bit & 1 == 1 {
                                x.setbit(by * 8 + bit);
                            }
                        }
                    }
                }
                if x.is_zero() {
                    x = Fe::from_u32(1);
                }
                let inv = field.field_invert(&x);
                let prod = field.field_mult(&x, &inv);
                assert!(prod.is_one(), "deg {} x*inv != 1", deg);
            }
        }
    }

    #[test]
    fn add_is_xor_and_selfinverse() {
        let a = Fe::from_hex(b"cafe").unwrap();
        let b = Fe::from_hex(b"beef").unwrap();
        let c = Fe::xor(&a, &b);
        // field_sub == field_add: a + b + b == a
        assert_eq!(Fe::xor(&c, &b), a);
    }

    #[test]
    fn mult_identity_and_commute() {
        let field = Field::init(128);
        let one = Fe::from_u32(1);
        let x = Fe::from_hex(b"0123456789abcdef0123456789abcdef").unwrap();
        assert_eq!(field.field_mult(&x, &one), x);
        let y = Fe::from_hex(b"fedcba98").unwrap();
        assert_eq!(field.field_mult(&x, &y), field.field_mult(&y, &x));
    }
}
