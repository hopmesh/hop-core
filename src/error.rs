//! Error types for hop-core.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("codec error: {0}")]
    Codec(#[from] postcard::Error),

    #[error("crypto error: {0}")]
    Crypto(&'static str),

    #[error("invalid key material")]
    InvalidKey,

    #[error("decompression failed")]
    Decompress,

    #[error("bundle signature verification failed")]
    BadSignature,

    #[error("unsupported wire format version {got} (this build speaks {supported})")]
    UnsupportedVersion { got: u8, supported: u8 },

    #[error("bundle expired or hop limit reached")]
    Undeliverable,

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = core::result::Result<T, Error>;
