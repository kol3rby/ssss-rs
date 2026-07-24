//! Cryptographic PRNG: the `/dev/urandom` reader (ssss.c:298-328).
//!
//! For test determinism the source path may be overridden with the
//! `SSSS_RANDOM_SOURCE` environment variable; unset it defaults to
//! `/dev/urandom`, so production behavior is unchanged. This is the fixed-byte-
//! source hook the interop tests rely on.

use crate::errors::SssErrcode;
use crate::field::Fe;
use crate::secure::secure_zero;
use std::fs::File;
use std::io::Read;

fn random_source() -> String {
    std::env::var("SSSS_RANDOM_SOURCE").unwrap_or_else(|_| crate::RANDOM_SOURCE.to_string())
}

/// Holds the open random source. Replaces the `int cprng` fd global; the file
/// closes on `Drop` (the RAII form of `cprng_deinit`).
#[derive(Default)]
pub struct Cprng {
    file: Option<File>,
}

impl Cprng {
    /// `enum ssss_errcode cprng_init(void)` (ssss.c:300).
    pub fn cprng_init(&mut self) -> Result<(), SssErrcode> {
        match File::open(random_source()) {
            Ok(f) => {
                self.file = Some(f);
                Ok(())
            }
            Err(_) => Err(SssErrcode::OpenRandom),
        }
    }

    /// `enum ssss_errcode cprng_deinit(void)` (ssss.c:306).
    pub fn cprng_deinit(&mut self) -> Result<(), SssErrcode> {
        // Dropping the File closes the fd. close() failure is not observable
        // through std, so we mirror the success path.
        self.file = None;
        Ok(())
    }

    /// `enum ssss_errcode cprng_read(mpz_t x)` (ssss.c:312). Reads exactly
    /// `degree/8` bytes (looping over short reads) and imports them big-endian.
    pub fn cprng_read(&mut self, degree: u32) -> Result<Fe, SssErrcode> {
        let n = (degree / 8) as usize;
        let mut buf = vec![0u8; n];
        let mut count = 0usize;
        let mut err = None;
        while count < n {
            let file = self.file.as_mut().expect("cprng not initialized");
            match file.read(&mut buf[count..]) {
                Ok(0) => {
                    // EOF from a short fixed source: treat as read failure.
                    self.file = None;
                    err = Some(SssErrcode::ReadRandom);
                    break;
                }
                Ok(i) => count += i,
                Err(_) => {
                    self.file = None;
                    err = Some(SssErrcode::ReadRandom);
                    break;
                }
            }
        }
        let result = match err {
            Some(e) => Err(e),
            None => Ok(Fe::import(&buf, n, 1, 1, 0)),
        };
        secure_zero(&mut buf);
        result
    }
}
