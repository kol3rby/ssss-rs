//! Cryptographic PRNG: the `/dev/urandom` reader.
//!
//! For test determinism the source path may be overridden with the
//! `SSSS_RANDOM_SOURCE` environment variable; unset it defaults to
//! `/dev/urandom`, so production behavior is unchanged. This is the fixed-byte-
//! source hook the interop tests rely on.

use crate::errors::Error;
use crate::field::Fe;
use crate::secure::secure_zero;
use std::fs::File;
use std::io::Read;

fn random_source() -> String {
    std::env::var("SSSS_RANDOM_SOURCE").unwrap_or_else(|_| crate::RANDOM_SOURCE.to_string())
}

/// Owns the open random source; the fd closes on `Drop`.
pub struct Cprng {
    file: File,
}

impl Cprng {
    /// Open the random source.
    pub fn open() -> Result<Cprng, Error> {
        match File::open(random_source()) {
            Ok(file) => Ok(Cprng { file }),
            Err(_) => Err(Error::OpenRandom),
        }
    }

    /// Read exactly `degree/8` bytes (looping over short reads) and import them
    /// big-endian.
    pub fn read(&mut self, degree: u32) -> Result<Fe, Error> {
        let n = (degree / 8) as usize;
        let mut buf = vec![0u8; n];
        let mut count = 0usize;
        let mut err = None;
        while count < n {
            match self.file.read(&mut buf[count..]) {
                // EOF from a short fixed source: treat as read failure.
                Ok(0) => {
                    err = Some(Error::ReadRandom);
                    break;
                }
                Ok(i) => count += i,
                Err(_) => {
                    err = Some(Error::ReadRandom);
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
