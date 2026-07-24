//! XTEA-based diffusion layer.
//!
//! Pure `u32` arithmetic with wrapping (overflowing) semantics, made explicit
//! via `wrapping_*`. The public surface is just [`encode`] and [`decode`]; the
//! direction flag and the per-block cipher stay internal (the latter as an
//! `impl Fn` closure argument to [`encode_slice`]).

use crate::field::Fe;

/// 32 XTEA rounds over a two-word block.
fn encipher_block(v: &mut [u32; 2]) {
    let delta: u32 = 0x9E37_79B9;
    let mut sum: u32 = 0;
    for _ in 0..32 {
        v[0] = v[0].wrapping_add((((v[1] << 4) ^ (v[1] >> 5)).wrapping_add(v[1])) ^ sum);
        sum = sum.wrapping_add(delta);
        v[1] = v[1].wrapping_add((((v[0] << 4) ^ (v[0] >> 5)).wrapping_add(v[0])) ^ sum);
    }
}

/// Inverse of [`encipher_block`].
fn decipher_block(v: &mut [u32; 2]) {
    let delta: u32 = 0x9E37_79B9;
    let mut sum: u32 = 0xC6EF_3720;
    for _ in 0..32 {
        v[1] = v[1].wrapping_sub((((v[0] << 4) ^ (v[0] >> 5)).wrapping_add(v[0])) ^ sum);
        sum = sum.wrapping_sub(delta);
        v[0] = v[0].wrapping_sub((((v[1] << 4) ^ (v[1] >> 5)).wrapping_add(v[1])) ^ sum);
    }
}

/// Read two big-endian u32 words at wrapped offsets, apply the block function,
/// and write them back.
fn encode_slice(data: &mut [u8], idx: usize, len: usize, process: impl Fn(&mut [u32; 2])) {
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

/// Direction of the diffusion transform.
#[derive(Copy, Clone, PartialEq, Eq)]
enum EncDec {
    Encode,
    Decode,
}

/// Apply the diffusion layer in place.
pub fn encode(x: &mut Fe, degree: u32) {
    encode_mpz(x, degree, EncDec::Encode);
}

/// Undo the diffusion layer in place.
pub fn decode(x: &mut Fe, degree: u32) {
    encode_mpz(x, degree, EncDec::Decode);
}

/// 40 rounds over (degree/8) slices — forward for `Encode`, reverse for
/// `Decode` — with the `degree % 16 == 8` byte fixup that shuffles the extra
/// buffer byte before and after the rounds.
fn encode_mpz(x: &mut Fe, degree: u32, mode: EncDec) {
    let deg = degree as usize;
    let vlen = (deg + 8) / 16 * 2;
    let mut v = vec![0u8; vlen];

    // Serialize as little-endian 2-byte words, big-endian within each word.
    let (exp, _t) = x.export(-1, 2, 1);
    v[..exp.len()].copy_from_slice(&exp);

    let dlen = deg / 8; // `len` (wrap modulus) passed to encode_slice
    if deg % 16 == 8 {
        v[dlen - 1] = v[dlen];
    }

    match mode {
        EncDec::Encode => {
            // Forward: slices 0, 2, ... up to 40 * (degree/8).
            let mut i = 0usize;
            let end = 40 * dlen;
            while i < end {
                encode_slice(&mut v, i, dlen, encipher_block);
                i += 2;
            }
        }
        EncDec::Decode => {
            // Reverse: the same slices in the opposite order.
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

    // Deserialize with the same layout used above.
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

    // encode() then decode() is the identity.
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
                encode(&mut x, deg);
                assert!(x.bits() <= deg as usize);
                decode(&mut x, deg);
                assert_eq!(x, orig, "deg {} encode/decode not identity", deg);
            }
        }
    }
}
