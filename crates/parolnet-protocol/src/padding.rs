//! Message padding to fixed bucket sizes (PNP-001 Section 3.6).
//!
//! All messages are padded to one of: 256, 1024, 4096, or 16384 bytes.
//! This prevents an observer from distinguishing message types by length.
//!
//! Padding format: the plaintext is prefixed with a 4-byte big-endian length,
//! followed by the original data, then random padding bytes to fill the bucket.

use crate::{BUCKET_SIZES, PaddingStrategy, ProtocolError};
use rand::RngCore;

/// Standard bucket-based padding strategy.
///
/// Pads messages to the smallest bucket size that fits, using
/// cryptographically random padding bytes.
///
/// # Examples
///
/// ```
/// use parolnet_protocol::padding::BucketPadding;
/// use parolnet_protocol::{PaddingStrategy, BUCKET_SIZES};
///
/// let payload = b"hello";
/// let padded = BucketPadding.pad(payload).unwrap();
/// assert!(BUCKET_SIZES.contains(&padded.len()));
/// assert_eq!(BucketPadding.unpad(&padded).unwrap(), payload);
/// ```
pub struct BucketPadding;

/// Overhead: 4 bytes for the length prefix.
const LENGTH_PREFIX_SIZE: usize = 4;

impl PaddingStrategy for BucketPadding {
    fn pad(&self, plaintext: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        let needed = plaintext.len() + LENGTH_PREFIX_SIZE;
        let max_bucket = *BUCKET_SIZES.last().unwrap();
        let bucket = match select_bucket(needed) {
            Some(b) => b,
            None => {
                return Err(ProtocolError::MessageTooLarge {
                    size: plaintext.len(),
                    max: max_bucket - LENGTH_PREFIX_SIZE,
                });
            }
        };

        let mut output = Vec::with_capacity(bucket);

        // 4-byte big-endian length prefix
        let len = plaintext.len() as u32;
        output.extend_from_slice(&len.to_be_bytes());

        // Original plaintext
        output.extend_from_slice(plaintext);

        // Random padding to fill the bucket
        let pad_len = bucket - output.len();
        if pad_len > 0 {
            let mut pad = vec![0u8; pad_len];
            rand::thread_rng().fill_bytes(&mut pad);
            output.extend_from_slice(&pad);
        }

        debug_assert_eq!(output.len(), bucket);
        Ok(output)
    }

    fn unpad(&self, padded: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        if padded.len() < LENGTH_PREFIX_SIZE {
            return Err(ProtocolError::PaddingError(
                "data too short for length prefix".into(),
            ));
        }

        if !BUCKET_SIZES.contains(&padded.len()) {
            return Err(ProtocolError::InvalidEnvelopeLength(padded.len()));
        }

        let len = u32::from_be_bytes([padded[0], padded[1], padded[2], padded[3]]) as usize;

        if LENGTH_PREFIX_SIZE + len > padded.len() {
            return Err(ProtocolError::PaddingError(format!(
                "length prefix {} exceeds padded data size {}",
                len,
                padded.len()
            )));
        }

        Ok(padded[LENGTH_PREFIX_SIZE..LENGTH_PREFIX_SIZE + len].to_vec())
    }
}

/// Select the smallest bucket size that can contain the given data length.
///
/// # Examples
///
/// ```
/// use parolnet_protocol::padding::select_bucket;
///
/// assert_eq!(select_bucket(1), Some(256));
/// assert_eq!(select_bucket(256), Some(256));
/// assert_eq!(select_bucket(257), Some(1024));
/// assert_eq!(select_bucket(16384), Some(16384));
/// assert_eq!(select_bucket(16385), None);
/// ```
pub fn select_bucket(data_len: usize) -> Option<usize> {
    BUCKET_SIZES.iter().copied().find(|&size| size >= data_len)
}
