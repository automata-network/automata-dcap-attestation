#[cfg(test)]
mod test;

pub mod async_proving;
use async_proving::bonsai_prove_non_blocking;

use anyhow::Result;
use borsh::{BorshDeserialize, BorshSerialize};
use ecdsa_sepc256r1_methods::ECDSA_SEPC256R1_GUEST_ELF;
use risc0_zkvm::{ExecutorEnv, InnerReceipt, ProverOpts, compute_image_id, default_prover};

#[derive(BorshDeserialize, BorshSerialize)]
pub struct Input {
    pub input_digest: [u8; 32],
    pub input_signature: [u8; 64],
    pub issuer_raw_der: Vec<u8>,
}

pub fn get_image_id() -> Result<String> {
    let image_id = compute_image_id(ECDSA_SEPC256R1_GUEST_ELF)?;
    Ok(image_id.to_string())
}

pub fn verify(
    input_digest: [u8; 32],
    input_signature: [u8; 64],
    issuer_raw_der: Vec<u8>,
) -> Result<(
    [u8; 32], // image_id
    Vec<u8>,  // journal_bytes
    Vec<u8>,  // Groth16 Seal
)> {
    let image_id = compute_image_id(ECDSA_SEPC256R1_GUEST_ELF)?;
    let serialized_input = serialize_input(input_digest, input_signature, issuer_raw_der)?;

    // Set RISC0_PROVER env to bonsai if using Groth16
    // I am asssuming that most people can't afford to run Groth16 prover locally
    std::env::set_var("RISC0_PROVER", "bonsai");
    let opts = ProverOpts::groth16();

    let env = ExecutorEnv::builder()
        .write_slice(&serialized_input)
        .build()?;

    let receipt = default_prover()
        .prove_with_opts(env, ECDSA_SEPC256R1_GUEST_ELF, &opts)?
        .receipt;

    let output = receipt.journal.bytes;
    let seal = match receipt.inner {
        InnerReceipt::Groth16(groth16_receipt) => groth16_receipt.seal,
        _ => unreachable!(),
    };

    Ok((image_id.into(), output, seal))
}

pub async fn verify_non_blocking(
    input_digest: [u8; 32],
    input_signature: [u8; 64],
    issuer_raw_der: Vec<u8>,
) -> Result<(
    [u8; 32], // image_id
    Vec<u8>,  // journal_bytes
    Vec<u8>,  // Groth16 Seal
)> {
    let image_id = compute_image_id(ECDSA_SEPC256R1_GUEST_ELF)?;
    let serialized_input = serialize_input(input_digest, input_signature, issuer_raw_der)?;

    let snark_receipt = bonsai_prove_non_blocking(
        ECDSA_SEPC256R1_GUEST_ELF, 
        &serialized_input,
        true
    ).await?;

    let output = snark_receipt.journal.bytes;
    let seal = match snark_receipt.inner {
        InnerReceipt::Groth16(groth16_receipt) => {
            groth16_receipt.seal
        },
        _ => unreachable!(),
    };

    Ok((image_id.into(), output, seal))
}

fn serialize_input(
    input_digest: [u8; 32],
    input_signature: [u8; 64],
    issuer_raw_der: Vec<u8>,
) -> Result<Vec<u8>> {
    let input = Input {
        input_digest,
        input_signature,
        issuer_raw_der,
    };
    let mut input_bytes = vec![];
    input.serialize(&mut input_bytes)?;
    Ok(input_bytes)
}
