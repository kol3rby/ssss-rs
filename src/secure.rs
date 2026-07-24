//! Secure memory manipulation.
//!
//! Secret-bearing buffers zero their backing store on `Drop` (see `field::Fe`),
//! so there is no separate zeroing allocator to install; `secure_zero` is the
//! shared primitive those drops call.

use std::sync::atomic::{compiler_fence, Ordering};

/// Zero a buffer with a volatile write loop the optimizer may not elide:
/// `write_volatile` plus a compiler fence so the stores survive `--release`.
pub fn secure_zero(s: &mut [u8]) {
    for p in s.iter_mut() {
        unsafe { std::ptr::write_volatile(p, 0u8) };
    }
    compiler_fence(Ordering::SeqCst);
}
