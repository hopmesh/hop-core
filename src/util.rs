//! Small shared utilities. Compression keeps gossip payloads and relay-cache
//! entries small — important because every device relays for others (DESIGN.md
//! §15–§16: "compression is key, keep relays light").

use crate::error::{Error, Result};

/// DEFLATE-compress a byte slice (pure-Rust, no C deps). Level 6 is a good
/// size/speed balance for small mesh payloads.
pub fn compress(data: &[u8]) -> Vec<u8> {
    miniz_oxide::deflate::compress_to_vec(data, 6)
}

/// Inverse of [`compress`].
pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    miniz_oxide::inflate::decompress_to_vec(data).map_err(|_| Error::Decompress)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compress_roundtrip() {
        let data = b"market market market bike bike bike for sale for sale".repeat(20);
        let packed = compress(&data);
        assert!(packed.len() < data.len());
        assert_eq!(decompress(&packed).unwrap(), data);
    }
}
