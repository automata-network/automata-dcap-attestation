// src/types/pod/tcb_info/zero_copy/mod.rs

pub mod error;
pub mod iterators;
pub mod structs;
pub mod utils;

#[cfg(feature = "full")]
pub mod conversion;

pub use error::ZeroCopyError;
pub use structs::{
    TcbComponentZeroCopy,
    // Potentially export intermediate payload structs if they are part of the public API
    TcbInfoZeroCopy,
    TcbLevelZeroCopy,
    TdxModuleIdentityZeroCopy,
    TdxModulePodDataZeroCopy,
    TdxTcbLevelZeroCopy,
};
// Iterators might also be exported if users need to name their types explicitly.
// pub use iterators::*;
