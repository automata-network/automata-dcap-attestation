use alloy_sol_types::sol;
use anyhow::{Context, Result, ensure};
use dcap_rs::types::collateral::Collateral;
use dcap_rs::v2::encode_guest_input_v2;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub type GuestInput = sol!((bytes, bytes, uint64));

/// Public signed input plus an immutable expected journal. JSON strings retain
/// the signed collateral bodies verbatim; never sort or rewrite their fields.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V2Fixture {
    pub fixture_version: u16,
    pub source: String,
    pub quote_version: u16,
    pub verification_timestamp: u64,
    pub tcb_evaluation_data_number: u32,
    pub quote: String,
    pub quote_sha256: String,
    pub root_ca_crl: String,
    pub pck_crl: String,
    pub tcb_signing_certificate: String,
    pub root_ca_certificate: String,
    pub platform_ca_certificate: String,
    pub tcb_info_json: String,
    pub qe_identity_json: String,
    pub guest_input: String,
    pub guest_input_sha256: String,
    pub expected_journal: String,
    pub expected_journal_sha256: String,
}

pub fn unhex(value: &str) -> Result<Vec<u8>> {
    hex::decode(value.strip_prefix("0x").context("missing 0x prefix")?)
        .context("invalid fixture hex")
}

pub fn hex_bytes(value: &[u8]) -> String {
    format!("0x{}", hex::encode(value))
}

pub fn sha256(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}

impl V2Fixture {
    pub fn rebuild_input(&self) -> Result<Vec<u8>> {
        ensure!(self.fixture_version == 1, "unsupported fixture version");
        let chain = format!(
            "{}{}",
            pem::encode(&pem::Pem::new(
                "CERTIFICATE",
                unhex(&self.tcb_signing_certificate)?
            )),
            pem::encode(&pem::Pem::new(
                "CERTIFICATE",
                unhex(&self.root_ca_certificate)?
            ))
        );
        let collateral = Collateral::new(
            &unhex(&self.root_ca_crl)?,
            &unhex(&self.pck_crl)?,
            chain.as_bytes(),
            &self.tcb_info_json,
            &self.qe_identity_json,
        )?;
        let quote = unhex(&self.quote)?;
        ensure!(sha256(&quote) == self.quote_sha256, "quote digest mismatch");
        let input = encode_guest_input_v2(&collateral, &quote, self.verification_timestamp)?;
        ensure!(input == unhex(&self.guest_input)?, "guest input changed");
        ensure!(
            sha256(&input) == self.guest_input_sha256,
            "input digest mismatch"
        );
        let expected = unhex(&self.expected_journal)?;
        ensure!(
            sha256(&expected) == self.expected_journal_sha256,
            "journal digest mismatch"
        );
        Ok(input)
    }
}
