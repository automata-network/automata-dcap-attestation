//! Intel Quote Provider Library (QPL) interface implementation.
//!
//! This crate provides a Rust implementation of the Intel SGX/TDX Quote Provider Library
//! interface for fetching and managing attestation collaterals. It includes functionality
//! for both cloud provider integrations (Azure) and on-chain collateral retrieval.
//!
//! # Modules
//!
//! - [`types`] - FFI type definitions matching Intel's QPL C interface
//! - [`collaterals`] - Collateral fetching and management functions
//! - [`ffi`] - FFI implementations of Intel QPL functions

/// FFI type definitions for Intel QPL interface.
pub mod types;

/// Collateral fetching and management utilities.
pub mod collaterals;

/// FFI function implementations for Intel QPL interface.
pub mod ffi;

// Re-export commonly used types for convenience
pub use types::*;

// Re-export commonly used collateral functions
pub use collaterals::{
    detect_missing_collateral, upload_missing_collaterals, sgx_ql_get_quote_config,
    sgx_ql_get_quote_verification_collateral, sgx_ql_get_qve_identity, sgx_ql_get_root_ca_crl,
    tdx_ql_get_quote_verification_collateral,
};

// Re-export from pccs-reader-rs
pub use pccs_reader_rs::{Collaterals, CollateralError, MissingCollateral, MissingCollateralReport};
