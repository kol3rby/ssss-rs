//! Polynomial evaluation and secret reconstruction (ssss.c:398-494).

use crate::field::{Fe, Field};

/// `void horner(int n, mpz_t y, const mpz_t x, const mpz_t coeff[])`
/// (ssss.c:404). Evaluates with the legacy extra x^k term. (Unused by
/// split/combine, kept for fidelity to the source.)
#[allow(dead_code)]
pub fn horner(field: &Field, n: usize, x: &Fe, coeff: &[Fe]) -> Fe {
    let mut y = x.clone();
    for i in (1..n).rev() {
        y = Fe::xor(&y, &coeff[i]);
        y = field.field_mult(&y, x);
    }
    Fe::xor(&y, &coeff[0])
}

/// `void horner_r(int n, mpz_t y, const mpz_t x, const mpz_t coeff_rev[])`
/// (ssss.c:418). `horner` with reversed coefficients (coeff_rev[i] is the
/// coefficient of x^(n-1-i)); used by split.
pub fn horner_r(field: &Field, n: usize, x: &Fe, coeff_rev: &[Fe]) -> Fe {
    let mut y = x.clone();
    for c in coeff_rev.iter().take(n - 1) {
        y = Fe::xor(&y, c);
        y = field.field_mult(&y, x);
    }
    Fe::xor(&y, &coeff_rev[n - 1])
}

/// `int restore_secret(int n, mpz_t (*A)[n], mpz_t b[], int recovery)`
/// (ssss.c:434). Gaussian elimination over the field. `a[i][j]` mirrors the C
/// `AA[i][j]` (treated as `AA[column][row]`). Returns 0 on success, -1 when no
/// pivot is found (-> inconsistent shares).
///
/// The `USE_RESTORE_SECRET_WORKAROUND` ifdef is dropped: Rust has no VLA
/// parameter-type portability issue.
pub fn restore_secret(
    field: &Field,
    n: usize,
    a: &mut [Vec<Fe>],
    b: &mut [Fe],
    recovery: bool,
) -> i32 {
    for i in 0..n {
        if a[i][i].is_zero() {
            let mut found = false;
            let mut j = i + 1;
            while j < n {
                if !a[i][j].is_zero() {
                    found = true;
                    break;
                }
                j += 1;
            }
            if !found {
                return -1;
            }
            // Column/row swaps mirror the C `MPZ_SWAP(AA[k][i], AA[k][j])`; the
            // index `k` walks the matrix rows, so keep it explicit.
            #[allow(clippy::needless_range_loop)]
            for k in i..n {
                a[k].swap(i, j);
            }
            b.swap(i, j);
        }
        for j in (i + 1)..n {
            if !a[i][j].is_zero() {
                for k in (i + 1)..n {
                    let h = field.field_mult(&a[k][i], &a[i][j]);
                    a[k][j] = field.field_mult(&a[k][j], &a[i][i]);
                    a[k][j] = Fe::xor(&a[k][j], &h);
                }
                let h = field.field_mult(&b[i], &a[i][j]);
                b[j] = field.field_mult(&b[j], &a[i][i]);
                b[j] = Fe::xor(&b[j], &h);
            }
        }
    }
    // Upper triangular now: calculate the last coefficient (the secret).
    let h = field.field_invert(&a[n - 1][n - 1]);
    b[n - 1] = field.field_mult(&b[n - 1], &h);
    if recovery {
        // Transform to identity and recover the other coefficients.
        for i in (0..(n - 1)).rev() {
            for j in ((i + 1)..n).rev() {
                let h = field.field_mult(&b[j], &a[j][i]);
                b[i] = Fe::xor(&b[i], &h);
            }
            let h = field.field_invert(&a[i][i]);
            b[i] = field.field_mult(&b[i], &h);
        }
    }
    0
}
