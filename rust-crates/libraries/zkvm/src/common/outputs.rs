use anyhow::Result;
use automata_dcap_utils::{parser::parse_output as utils_parse_output, Version};
use dcap_rs::types::VerifiedOutput;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Parse the output journal from the guest program (version-aware)
///
/// # Arguments
/// * `output` - Raw output bytes from zkVM journal/public values
/// * `version` - DCAP deployment version (v1.0 or v1.1)
///
/// # Returns
/// Parsed output structure containing VerifiedOutput and collateral hashes
pub fn parse_output(output: &[u8], version: Version) -> Result<ParsedOutput> {
    let mut offset: usize = 0;
    let output_len = u16::from_be_bytes(output[offset..offset + 2].try_into()?);

    offset += 2;
    let raw_verified_output = &output[offset..offset + output_len as usize];

    // Use utils crate for version-aware VerifiedOutput parsing
    let verified_output = utils_parse_output(raw_verified_output, version)?;
    offset += output_len as usize;

    let current_time = u64::from_be_bytes(output[offset..offset + 8].try_into()?);
    offset += 8;
    let tcbinfo_root_hash = output[offset..offset + 32].to_vec();
    offset += 32;
    let enclaveidentity_root_hash = output[offset..offset + 32].to_vec();
    offset += 32;
    let root_cert_hash = output[offset..offset + 32].to_vec();
    offset += 32;
    let signing_cert_hash = output[offset..offset + 32].to_vec();
    offset += 32;
    let root_crl_hash = output[offset..offset + 32].to_vec();
    offset += 32;
    let pck_crl_hash = output[offset..offset + 32].to_vec();

    Ok(ParsedOutput {
        verified_output,
        current_time,
        tcbinfo_root_hash,
        enclaveidentity_root_hash,
        root_cert_hash,
        signing_cert_hash,
        root_crl_hash,
        pck_crl_hash,
    })
}

/// Structured output from parsing the guest program journal
pub struct ParsedOutput {
    pub verified_output: VerifiedOutput,
    pub current_time: u64,
    pub tcbinfo_root_hash: Vec<u8>,
    pub enclaveidentity_root_hash: Vec<u8>,
    pub root_cert_hash: Vec<u8>,
    pub signing_cert_hash: Vec<u8>,
    pub root_crl_hash: Vec<u8>,
    pub pck_crl_hash: Vec<u8>,
}

/// Proof artifact that can be serialized to JSON
#[derive(Debug, Serialize, Deserialize)]
pub struct ProofArtifact {
    pub zkvm: String,
    pub circuit_version: String,
    pub program_id: String,
    pub journal: String,
    pub proof: String,
}

/// Write proof artifact to a JSON file
pub fn write_proof_artifact(output_path: &Path, artifact: &ProofArtifact) -> Result<()> {
    // Create parent directories if they don't exist
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let json = serde_json::to_string_pretty(artifact)?;
    std::fs::write(output_path, json)?;
    println!("Proof artifact written to: {}", output_path.display());
    Ok(())
}
