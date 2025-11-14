// src/types/pod/enclave_identity/zero_copy/mod.rs

pub mod error;
pub mod iterators;
pub mod structs;

#[cfg(feature = "full")]
pub mod conversion;

pub use error::ZeroCopyError; // error.rs is a submodule
pub use structs::{
    // structs.rs is a submodule
    EnclaveIdentityZeroCopy,
    QeTcbLevelZeroCopy,
};
// We might not need to export iterators directly if they are only used internally
// by methods on the ZeroCopy structs.
// pub use iterators::*; // Example if iterators need to be named by users
