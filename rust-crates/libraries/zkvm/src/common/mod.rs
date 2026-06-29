//! Common DCAP verification workflow shared across all zkVM backends.
//!
//! This module contains zkVM-agnostic code for the DCAP attestation verification process,
//! including quote reading, collateral fetching, input/output serialization, and formatting.
//!
//! When compiled with `guest` feature only, this module provides minimal types for
//! zkVM guest programs (GuestInput, GuestInputSolType).

// Always available - minimal types for guest programs
pub mod inputs;

// Host-only modules
#[cfg(feature = "host")]
pub mod display;
#[cfg(feature = "host")]
pub mod outputs;
#[cfg(feature = "host")]
pub mod quote;
#[cfg(feature = "host")]
pub mod traits;
#[cfg(feature = "host")]
pub mod types;
#[cfg(feature = "host")]
pub mod workflow;

// Host-only re-exports
#[cfg(feature = "host")]
pub use display::display_proof_result;
#[cfg(feature = "host")]
pub use inputs::generate_input;
#[cfg(feature = "host")]
pub use outputs::{parse_output, ParsedOutput, ProofArtifact, write_proof_artifact};
#[cfg(feature = "host")]
pub use quote::QuoteMetadata;
#[cfg(feature = "host")]
pub use traits::ZkVmProver;
#[cfg(feature = "host")]
pub use types::ZkVm;
#[cfg(feature = "host")]
pub use workflow::prepare_guest_input;
