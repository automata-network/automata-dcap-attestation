// src/types/pod/enclave_identity/zero_copy/error.rs

use bytemuck::PodCastError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZeroCopyError {
    InvalidSliceLength,
    InvalidOffset,
    InvalidEnumValue,
    InvalidUtf8,
    BytemuckError(PodCastError),
    // Add other specific errors as needed
}

impl ZeroCopyError {
    pub fn from_bytemuck_error(e: PodCastError) -> Self {
        ZeroCopyError::BytemuckError(e)
    }
}

impl core::fmt::Display for ZeroCopyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ZeroCopyError::InvalidSliceLength => write!(
                f,
                "Invalid slice length encountered during zero-copy parsing"
            ),
            ZeroCopyError::InvalidOffset => {
                write!(f, "Invalid offset calculated during zero-copy parsing")
            },
            ZeroCopyError::InvalidEnumValue => write!(f, "Invalid enum value encountered"),
            ZeroCopyError::InvalidUtf8 => {
                write!(f, "Invalid UTF-8 sequence encountered in string data")
            },
            ZeroCopyError::BytemuckError(e) => write!(f, "Bytemuck PodCastError: {:?}", e),
        }
    }
}

// Implement std::error::Error if it's intended to be used with `anyhow` or similar.
// impl std::error::Error for ZeroCopyError {}
