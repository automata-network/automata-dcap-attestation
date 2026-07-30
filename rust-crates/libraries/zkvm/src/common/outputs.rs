use anyhow::{Context, Result};
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
    let output_len = u16::from_be_bytes(
        take(output, &mut offset, 2, "verified output length")?
            .try_into()
            .context("verified output length has the wrong size")?,
    );
    let raw_verified_output = take(
        output,
        &mut offset,
        usize::from(output_len),
        "verified output",
    )?;

    // Use utils crate for version-aware VerifiedOutput parsing
    let verified_output = utils_parse_output(raw_verified_output, version)?;

    let current_time = u64::from_be_bytes(
        take(output, &mut offset, 8, "current time")?
            .try_into()
            .context("current time has the wrong size")?,
    );
    let tcbinfo_root_hash = take(output, &mut offset, 32, "TCB Info root hash")?.to_vec();
    let enclaveidentity_root_hash =
        take(output, &mut offset, 32, "Enclave Identity root hash")?.to_vec();
    let root_cert_hash = take(output, &mut offset, 32, "root certificate hash")?.to_vec();
    let signing_cert_hash = take(output, &mut offset, 32, "signing certificate hash")?.to_vec();
    let root_crl_hash = take(output, &mut offset, 32, "root CRL hash")?.to_vec();
    let pck_crl_hash = take(output, &mut offset, 32, "PCK CRL hash")?.to_vec();

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

fn take<'a>(input: &'a [u8], offset: &mut usize, length: usize, field: &str) -> Result<&'a [u8]> {
    let end = offset
        .checked_add(length)
        .with_context(|| format!("{field} offset overflow"))?;
    let value = input.get(*offset..end).with_context(|| {
        format!(
            "output is truncated while reading {field}: need {length} bytes at offset {}, total length {}",
            *offset,
            input.len()
        )
    })?;
    *offset = end;
    Ok(value)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_parser_returns_errors_for_truncated_inputs() {
        for input in [Vec::new(), vec![0], vec![0, 8], vec![0, 1, 0]] {
            let result = std::panic::catch_unwind(|| parse_output(&input, Version::V1_0));
            assert!(
                result.is_ok(),
                "output parser panicked for {} bytes",
                input.len()
            );
            assert!(
                result.unwrap().is_err(),
                "output parser accepted {} truncated bytes",
                input.len()
            );
        }
    }
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
