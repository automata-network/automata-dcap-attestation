//! zkVM integration for DCAP attestation verification.
//!
//! This crate provides zero-knowledge proof generation for Intel SGX/TDX attestation
//! verification using multiple zkVM backends (RISC Zero, SP1, Pico). It includes
//! versioned guest programs and host-side tooling for generating and verifying proofs.
//!
//! # Features
//!
//! - `guest` - Minimal feature for zkVM guest programs (input/output types only)
//! - `host` - Host-side dependencies (enabled by default)
//! - `risc0` - Enable RISC Zero backend
//! - `sp1` - Enable Succinct SP1 backend
//! - `pico` - Enable Pico backend (v1.1+ only)
//!
//! # Example (Host)
//!
//! ```no_run
//! use automata_dcap_zkvm::{ZkVm, Version, generate_input};
//!
//! # async fn example() -> anyhow::Result<()> {
//! // Generate prover input for a quote
//! let quote_bytes = vec![/* ... */];
//! let input = generate_input(
//!     &quote_bytes,
//!     Version::V1_1,
//!     ZkVm::Sp1,
//!     None, // network
//!     None, // private key
//! ).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Example (Guest)
//!
//! ```ignore
//! use automata_dcap_zkvm::common::inputs::{GuestInput, GuestInputSolType};
//!
//! let input = GuestInput::sol_abi_decode(&input_bytes);
//! ```

// Shared modules (always available)
pub mod common;

// zkVM-specific modules (feature-gated, requires host)
// Each zkVM module contains versioned guest programs under guest/v1_x/
#[cfg(feature = "risc0")]
pub mod risc0;

#[cfg(feature = "sp1")]
pub mod sp1;

#[cfg(feature = "pico")]
pub mod pico;

// Re-export commonly used types and functions (host-only)
#[cfg(feature = "host")]
pub use automata_dcap_utils::Version;
#[cfg(feature = "host")]
pub use common::{
    display_proof_result, generate_input, parse_output, prepare_guest_input, ParsedOutput,
    ProofArtifact, QuoteMetadata, ZkVm, ZkVmProver,
};

// Re-export guest types (always available)
pub use common::inputs::{GuestInput, GuestInputSolType};

// Re-export zkVM CLI commands for apps/cli integration
#[cfg(feature = "risc0")]
pub use risc0::{run as run_risc0_command, Risc0Command, Risc0ProveArgs, Risc0Prover};

#[cfg(feature = "sp1")]
pub use sp1::{run as run_sp1_command, Sp1Command, Sp1ProveArgs, Sp1Prover};

#[cfg(feature = "pico")]
pub use pico::{
    run as run_pico_command, PicoCommand, PicoProveArgs, PicoProveStrategy,
    PicoLocalProveArgs, PicoMarketplaceProveArgs, PicoProver,
    MarketplaceConfig, PicoConfig, ProvingStrategy,
};

// ============================================================================
// Version-Aware Helper Functions (Host-only)
// ============================================================================

/// Retrieves the guest program ELF binary for a specific DCAP version and zkVM backend.
///
/// # Arguments
///
/// * `version` - DCAP deployment version (v1.0 or v1.1)
/// * `zkvm` - zkVM backend type (RISC Zero, SP1, or Pico)
///
/// # Returns
///
/// Static reference to the ELF binary bytes
///
/// # Errors
///
/// Returns an error if:
/// - The requested zkVM feature is not enabled at compile time
/// - Pico is requested for v1.0 (not supported)
#[cfg(feature = "host")]
pub fn get_elf(version: Version, zkvm: ZkVm) -> anyhow::Result<&'static [u8]> {
    match (version, zkvm) {
        // v1.0 ELFs
        #[cfg(feature = "risc0")]
        (Version::V1_0, ZkVm::Risc0) => Ok(risc0::guest::v1_0::elf::DCAP_ELF),
        #[cfg(feature = "sp1")]
        (Version::V1_0, ZkVm::Sp1) => Ok(sp1::guest::v1_0::elf::DCAP_ELF),
        (Version::V1_0, ZkVm::Pico) => {
            anyhow::bail!("Pico is not supported in v1.0")
        }

        // v1.1 ELFs
        #[cfg(feature = "risc0")]
        (Version::V1_1, ZkVm::Risc0) => Ok(risc0::guest::v1_1::elf::DCAP_ELF),
        #[cfg(feature = "sp1")]
        (Version::V1_1, ZkVm::Sp1) => Ok(sp1::guest::v1_1::elf::DCAP_ELF),
        #[cfg(feature = "pico")]
        (Version::V1_1, ZkVm::Pico) => Ok(pico::guest::v1_1::elf::DCAP_ELF),

        // Catch-all for disabled features
        #[allow(unreachable_patterns)]
        _ => anyhow::bail!("zkVM {:?} is not enabled (feature not compiled)", zkvm),
    }
}
