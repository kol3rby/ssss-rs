//! XTEA-based diffusion layer (ssss.c:330-396).
//!
//! Pure `u32` arithmetic that must match the C to the bit. C relied on unsigned
//! overflow; Rust makes it explicit with `wrapping_*`.

use crate::field::Fe;

/// `void encipher_block(uint32_t *v)` (ssss.c:332). 32 XTEA rounds.
pub fn encipher_block(v: &mut [u32; 2]) {
    let delta: u32 = 0x9E37_79B9;
    let mut sum: u32 = 0;
    for _ in 0..32 {
        v[0] = v[0].wrapping_add((((v[1] << 4) ^ (v[1] >> 5)).wrapping_add(v[1])) ^ sum);
        sum = sum.wrapping_add(delta);
        v[1] = v[1].wrapping_add((((v[0] << 4) ^ (v[0] >> 5)).wrapping_add(v[0])) ^ sum);
    }
}

/// `void decipher_block(uint32_t *v)` (ssss.c:343). Inverse of the above.
pub fn decipher_block(v: &mut [u32; 2]) {
    let delta: u32 = 0x9E37_79B9;
    let mut sum: u32 = 0xC6EF_3720;
    for _ in 0..32 {
        v[1] = v[1].wrapping_sub((((v[0] << 4) ^ (v[0] >> 5)).wrapping_add(v[0])) ^ sum);
        sum = sum.wrapping_sub(delta);
        v[0] = v[0].wrapping_sub((((v[1] << 4) ^ (v[1] >> 5)).wrapping_add(v[1])) ^ sum);
    }
}

/// `void encode_slice(uint8_t *data, int idx, int len, void (*process_block)())`
/// (ssss.c:354). Reads two big-endian u32 words at wrapped offsets, applies the
/// block function, writes them back.
pub fn encode_slice(data: &mut [u8], idx: usize, len: usize, process: fn(&mut [u32; 2])) {
    let mut v = [0u32; 2];
    for (i, vi) in v.iter_mut().enumerate() {
        *vi = (data[(idx + 4 * i) % len] as u32) << 24
            | (data[(idx + 4 * i + 1) % len] as u32) << 16
            | (data[(idx + 4 * i + 2) % len] as u32) << 8
            | (data[(idx + 4 * i + 3) % len] as u32);
    }
    process(&mut v);
    for (i, &vi) in v.iter().enumerate() {
        data[(idx + 4 * i) % len] = (vi >> 24) as u8;
        data[(idx + 4 * i + 1) % len] = (vi >> 16) as u8;
        data[(idx + 4 * i + 2) % len] = (vi >> 8) as u8;
        data[(idx + 4 * i + 3) % len] = vi as u8;
    }
}

/// `enum encdec {ENCODE, DECODE}` (ssss.c:373).
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum EncDec {
    Encode,
    Decode,
}

/// `void encode_mpz(mpz_t x, enum encdec encdecmode)` (ssss.c:375).
///
/// `degree` replaces the global. 40 rounds over (degree/8) slices, forward for
/// ENCODE and reverse for DECODE, with the `degree % 16 == 8` byte fixup that
/// shuffles the extra buffer byte before and after the rounds.
pub fn encode_mpz(x: &mut Fe, degree: u32, mode: EncDec) {
    let deg = degree as usize;
    let vlen = (deg + 8) / 16 * 2;
    let mut v = vec![0u8; vlen];

    // mpz_export(v, &t, -1, 2, 1, 0, x): little-endian 2-byte big-endian words.
    let (exp, _t) = x.export(-1, 2, 1);
    v[..exp.len()].copy_from_slice(&exp);

    let dlen = deg / 8; // `len` argument to encode_slice
    if deg % 16 == 8 {
        v[dlen - 1] = v[dlen];
    }

    match mode {
        EncDec::Encode => {
            // for (i = 0; i < 40 * (degree/8); i += 2)
            let mut i = 0usize;
            let end = 40 * dlen;
            while i < end {
                encode_slice(&mut v, i, dlen, encipher_block);
                i += 2;
            }
        }
        EncDec::Decode => {
            // for (i = 40 * (degree/8) - 2; i >= 0; i -= 2)
            let mut i = 40 * dlen as i64 - 2;
            while i >= 0 {
                encode_slice(&mut v, i as usize, dlen, decipher_block);
                i -= 2;
            }
        }
    }

    if deg % 16 == 8 {
        v[dlen] = v[dlen - 1];
        v[dlen - 1] = 0;
    }

    // mpz_import(x, (degree + 8) / 16, -1, 2, 1, 0, v)
    *x = Fe::import(&v, (deg + 8) / 16, -1, 2, 1);
    debug_assert!(x.bits() <= deg);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::Fe;

    #[test]
    fn block_roundtrip() {
        let mut v = [0x0123_4567u32, 0x89ab_cdefu32];
        let orig = v;
        encipher_block(&mut v);
        assert_ne!(v, orig);
        decipher_block(&mut v);
        assert_eq!(v, orig);
    }

    // encode_mpz(ENCODE) then DECODE is the identity.
    #[test]
    fn encode_mpz_roundtrip() {
        let mut state: u64 = 0xdead_beef_cafe_babe;
        let mut rng = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        // Include degrees where degree % 16 == 8 (72, 88, ...) to exercise the
        // byte fixup, plus 64/128/1024.
        for &deg in &[64u32, 72, 88, 120, 128, 256, 1024] {
            for _ in 0..8 {
                let mut x = Fe::zero();
                for by in 0..(deg / 8) as usize {
                    let r = (rng() & 0xff) as u8;
                    for bit in 0..8 {
                        if r >> bit & 1 == 1 {
                            x.setbit(by * 8 + bit);
                        }
                    }
                }
                // keep it within the field
                if x.bits() > deg as usize {
                    continue;
                }
                let orig = x.clone();
                encode_mpz(&mut x, deg, EncDec::Encode);
                assert!(x.bits() <= deg as usize);
                encode_mpz(&mut x, deg, EncDec::Decode);
                assert_eq!(x, orig, "deg {} encode/decode not identity", deg);
            }
        }
    }
}
