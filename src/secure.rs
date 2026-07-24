//! Secure memory manipulation (ssss.c:730-754).
//!
//! Under backend (A) there is no GMP allocator to hook, so `secure_free` /
//! `secure_realloc` / `mp_set_memory_functions` collapse into RAII: field
//! elements zero their backing store on `Drop` (see `field::Fe`). We keep a
//! `secure_zero` function with the original name and semantics.

use std::sync::atomic::{compiler_fence, Ordering};

/// `void secure_zero(void *s, size_t n)` (ssss.c:732).
///
/// A volatile write loop that the optimizer may not elide. In C this used a
/// `volatile char *`; in Rust we use `write_volatile` plus a compiler fence so
/// the stores survive `--release`.
pub fn secure_zero(s: &mut [u8]) {
    for p in s.iter_mut() {
        unsafe { std::ptr::write_volatile(p, 0u8) };
    }
    compiler_fence(Ordering::SeqCst);
}
