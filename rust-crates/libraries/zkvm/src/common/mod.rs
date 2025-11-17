//! Common DCAP verification workflow shared across all zkVM backends.
//!
//! This module contains zkVM-agnostic code for the DCAP attestation verification process,
//! including quote reading, collateral fetching, input/output serialization, and formatting.

pub mod display;
pub mod inputs;
pub mod outputs;
pub mod quote;
pub mod traits;
pub mod types;
pub mod workflow;

pub use display::display_proof_result;
pub use inputs::generate_input;
pub use outputs::{parse_output, ParsedOutput, ProofArtifact, write_proof_artifact};
pub use quote::QuoteMetadata;
pub use traits::ZkVmProver;
pub use types::ZkVm;
pub use workflow::prepare_guest_input;
