use super::*;
use anyhow::Result;

use anchor_lang::declare_program;
declare_program!(dcap_ecdsa_sp1);

use dcap_p256_sp1_lib::{ProofType, get_proof};

pub struct SP1RequestArguments {
    pub input_type: InputType,
    pub subject_data: Vec<u8>,
    pub issuer_raw_der: Vec<u8>,
}

impl RequestProof for SP1RequestArguments {
    async fn request_p256_proof(&self) -> Result<([u8; 32], Vec<u8>, Vec<u8>)> {
        // let (vkey, output_bytes, proof_bytes) = get_proof(
        //     ProofType::Groth16,
        //     self.input_type,
        //     self.subject_data.clone(),
        //     self.issuer_raw_der.clone(),
        // )?;

        // Ok((vkey, output_bytes, proof_bytes))

        let input_type = self.input_type;
        let subject_data = self.subject_data.clone();
        let issuer_raw_der = self.issuer_raw_der.clone();

        // SP1 SDK is not async, so we need to spawn a blocking task
        tokio::task::spawn_blocking(move || {
            get_proof(ProofType::Groth16, input_type, subject_data, issuer_raw_der)
        })
        .await?
    }
}
