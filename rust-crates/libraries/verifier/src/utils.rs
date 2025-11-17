//! Utilities for reading and parsing zkVM proof artifacts
//!
//! # Example Usage
//!
//! ```no_run
//! use automata_dcap_verifier::utils::read_proof_artifact;
//! use automata_dcap_verifier::verify_and_attest_with_zk_proof;
//! use alloy::providers::ProviderBuilder;
//!
//! # async fn example() -> anyhow::Result<()> {
//! // Read and parse proof artifact from JSON
//! let parsed = read_proof_artifact("output/boundless.json")?;
//!
//! // Create provider
//! let provider = ProviderBuilder::new().on_builtin("http://localhost:8545").await?;
//!
//! // Verify with parsed data
//! let verified_output = verify_and_attest_with_zk_proof(
//!     &provider,
//!     &parsed.output_bytes,
//!     parsed.zk_coprocessor,
//!     &parsed.proof_bytes,
//!     Some(parsed.program_identifier),
//!     None, // tcb_eval_data_num
//! ).await?;
//!
//! println!("Verification successful: {}", verified_output);
//! # Ok(())
//! # }
//! ```

use crate::ZkCoprocessor;
use alloy::primitives::FixedBytes;
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Proof artifact that can be deserialized from JSON
#[derive(Debug, Serialize, Deserialize)]
pub struct ProofArtifact {
    pub zkvm: String,
    pub program_id: String,
    pub journal: String,
    pub proof: String,
}

/// Parsed proof data ready for on-chain verification
#[derive(Debug)]
pub struct ParsedProofData {
    /// The zkVM coprocessor type
    pub zk_coprocessor: ZkCoprocessor,
    /// The journal/output bytes (hex-decoded)
    pub output_bytes: Vec<u8>,
    /// The proof bytes (hex-decoded)
    pub proof_bytes: Vec<u8>,
    /// The program identifier as bytes32
    pub program_identifier: FixedBytes<32>,
}

impl ProofArtifact {
    /// Read a proof artifact from a JSON file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let json_str = std::fs::read_to_string(path.as_ref())
            .context(format!("Failed to read file: {}", path.as_ref().display()))?;

        let artifact: ProofArtifact = serde_json::from_str(&json_str)
            .context("Failed to parse JSON")?;

        Ok(artifact)
    }

    /// Parse the proof artifact into data ready for verification
    pub fn parse(&self) -> Result<ParsedProofData> {
        // Parse zkVM type
        let zk_coprocessor = match self.zkvm.to_lowercase().as_str() {
            "risc0" => ZkCoprocessor::Risc0,
            "sp1" => ZkCoprocessor::Sp1,
            "pico" => ZkCoprocessor::Pico,
            _ => return Err(anyhow!("Unknown zkVM type: {}", self.zkvm)),
        };

        // Decode hex strings
        let output_bytes = hex::decode(&self.journal)
            .context("Failed to decode journal hex")?;

        let proof_bytes = hex::decode(&self.proof)
            .context("Failed to decode proof hex")?;

        let program_id_bytes = hex::decode(&self.program_id)
            .context("Failed to decode program_id hex")?;

        // Convert program_id to FixedBytes<32>
        if program_id_bytes.len() != 32 {
            return Err(anyhow!(
                "Invalid program_id length: expected 32 bytes, got {}",
                program_id_bytes.len()
            ));
        }

        let program_identifier = FixedBytes::<32>::from_slice(&program_id_bytes);

        Ok(ParsedProofData {
            zk_coprocessor,
            output_bytes,
            proof_bytes,
            program_identifier,
        })
    }
}

/// Read and parse a proof artifact from a JSON file in one step
pub fn read_proof_artifact<P: AsRef<Path>>(path: P) -> Result<ParsedProofData> {
    let artifact = ProofArtifact::from_file(path)?;
    artifact.parse()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_boundless_json() {
        let cargo_manifest_dir = env!("CARGO_MANIFEST_DIR");
        let json_path = format!("{}/../../output/boundless.json", cargo_manifest_dir);

        // Skip test if file doesn't exist
        if !std::path::Path::new(&json_path).exists() {
            eprintln!("Skipping test: boundless.json not found at {}", json_path);
            return;
        }

        let parsed = read_proof_artifact(&json_path).unwrap();

        // Verify parsed data
        assert_eq!(parsed.zk_coprocessor, ZkCoprocessor::Risc0);
        assert!(!parsed.output_bytes.is_empty());
        assert!(!parsed.proof_bytes.is_empty());
        assert_eq!(parsed.program_identifier.len(), 32);

        println!("Successfully parsed proof artifact:");
        println!("  zkVM: {:?}", parsed.zk_coprocessor);
        println!("  Output bytes: {}", hex::encode(&parsed.output_bytes));
        println!("  Proof bytes: {}", hex::encode(&parsed.proof_bytes));
        println!("  Program ID: {}", hex::encode(&parsed.program_identifier));
    }
}
