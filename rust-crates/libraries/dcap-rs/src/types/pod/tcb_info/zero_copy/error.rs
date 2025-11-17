// src/types/pod/tcb_info/zero_copy/error.rs

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ZeroCopyError {
    InvalidSliceLength,
    InvalidUtf8,
    InvalidOffset,
    DataNotPresent,
    InvalidEnumValue,
    AlignmentError,
    OutputWouldHaveSlop,
    PodCastError,
    UnexpectedSgxComponentCount,
    NoMatchingSgxTcbLevel,
    MissingTdxComponentsInTcbInfo,
}

impl ZeroCopyError {
    // Helper function to create ZeroCopyError from bytemuck::PodCastError
    // This should be pub(super) if cast_slice is in the same module, or pub if used more widely.
    // Assuming it's used within the zero_copy module:
    pub(super) fn from_bytemuck_error(e: bytemuck::PodCastError) -> Self {
        match e {
            bytemuck::PodCastError::TargetAlignmentGreaterAndInputNotAligned => {
                ZeroCopyError::AlignmentError
            },
            bytemuck::PodCastError::OutputSliceWouldHaveSlop => ZeroCopyError::OutputWouldHaveSlop,
            bytemuck::PodCastError::SizeMismatch => ZeroCopyError::InvalidSliceLength, // Or a more specific SizeMismatch variant
            _ => ZeroCopyError::PodCastError,
        }
    }
}

impl core::fmt::Display for ZeroCopyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            ZeroCopyError::InvalidSliceLength => "Invalid slice length encountered during parsing",
            ZeroCopyError::InvalidUtf8 => "Invalid UTF-8 sequence encountered",
            ZeroCopyError::InvalidOffset => "Invalid offset calculation or out of bounds",
            ZeroCopyError::DataNotPresent => "Expected data not present where indicated",
            ZeroCopyError::InvalidEnumValue => "Invalid value for enum conversion",
            ZeroCopyError::AlignmentError => {
                "Input slice is not sufficiently aligned for the target type"
            },
            ZeroCopyError::OutputWouldHaveSlop => {
                "Output slice would have uninitialized trailing padding bytes"
            },
            ZeroCopyError::PodCastError => "A general bytemuck PodCastError occurred",
            ZeroCopyError::UnexpectedSgxComponentCount => {
                "Unexpected number of SGX TCB components encountered"
            },
            ZeroCopyError::NoMatchingSgxTcbLevel => {
                "No matching SGX TCB level found for the provided PCK extension"
            },
            ZeroCopyError::MissingTdxComponentsInTcbInfo => {
                "TDX TCB components missing in TCB Info for a TDX quote"
            },
        };
        write!(f, "{}", msg)
    }
}

// Optionally, implement std::error::Error if this needs to interoperate with other error types
// impl std::error::Error for ZeroCopyError {}
