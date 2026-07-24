//! Polynomial evaluation and secret reconstruction.

use crate::field::{Fe, Field};

/// Horner evaluation over reversed coefficients (`coeff_rev[i]` is the
/// coefficient of x^(n-1-i)), carrying the legacy extra x^k term; used by split.
pub fn horner_r(field: &Field, n: usize, x: &Fe, coeff_rev: &[Fe]) -> Fe {
    let mut y = x.clone();
    for c in coeff_rev.iter().take(n - 1) {
        y = &y + c;
        y = field.mul(&y, x);
    }
    &y + &coeff_rev[n - 1]
}

/// Gaussian elimination over the field, with `a` indexed `[column][row]`.
/// Returns 0 on success, -1 when no pivot is found (-> inconsistent shares).
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
            // Swap columns i and j across every row (`k` walks the rows).
            #[allow(clippy::needless_range_loop)]
            for k in i..n {
                a[k].swap(i, j);
            }
            b.swap(i, j);
        }
        for j in (i + 1)..n {
            if !a[i][j].is_zero() {
                for k in (i + 1)..n {
                    let h = field.mul(&a[k][i], &a[i][j]);
                    a[k][j] = field.mul(&a[k][j], &a[i][i]);
                    a[k][j] = &a[k][j] + &h;
                }
                let h = field.mul(&b[i], &a[i][j]);
                b[j] = field.mul(&b[j], &a[i][i]);
                b[j] = &b[j] + &h;
            }
        }
    }
    // Upper triangular now: calculate the last coefficient (the secret).
    let h = field.invert(&a[n - 1][n - 1]);
    b[n - 1] = field.mul(&b[n - 1], &h);
    if recovery {
        // Transform to identity and recover the other coefficients.
        for i in (0..(n - 1)).rev() {
            for j in ((i + 1)..n).rev() {
                let h = field.mul(&b[j], &a[j][i]);
                b[i] = &b[i] + &h;
            }
            let h = field.invert(&a[i][i]);
            b[i] = field.mul(&b[i], &h);
        }
    }
    0
}
