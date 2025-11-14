//! Auto-generated Rust bindings for Automata DCAP smart contracts.
//!
//! This crate contains Alloy-generated bindings for interacting with the
//! Automata DCAP on-chain contracts. These bindings are automatically generated
//! from the Solidity contract ABIs.
//!
//! # Usage
//!
//! ```no_run
//! use automata_dcap_evm_bindings::i_automata_dcap_attestation::IAutomataDcapAttestation;
//! use alloy::providers::ProviderBuilder;
//! use alloy::primitives::{Address, Bytes};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let provider = ProviderBuilder::new().on_builtin("http://localhost:8545").await?;
//! let contract_address = Address::ZERO; // Replace with actual address
//! let contract = IAutomataDcapAttestation::new(contract_address, &provider);
//!
//! // Call contract methods
//! let quote_bytes = Bytes::from(vec![/* ... */]);
//! let result = contract.verifyAndAttestOnChain_1(quote_bytes).call().await?;
//! # Ok(())
//! # }
//! ```

#![allow(clippy::all, rustdoc::all)]

#[path = "bindings/mod.rs"]
mod bindings;

pub use bindings::*;
