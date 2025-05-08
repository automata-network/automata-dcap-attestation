use anyhow::Result;
use ecdsa_secp256r1_host::{InputType, verify_non_blocking};

/// We use the ecdsa guest program here instead becasue
/// we are not verifying the entire chain
/// the ecdsa guest program can also be used to verify JSON collaterals

pub async fn get_ecdsa_verify_proof(
    input_type: InputType,
    input_data: &[u8],
    issuer_der: &[u8],
    issuer_crl: Option<&[u8]>
) -> Result<(
    [u8; 32], // image_id
    Vec<u8>,  // journal_bytes
    Vec<u8>,  // Groth16 Seal
)> {
    let (image_id, journal, seal) = verify_non_blocking(
        input_type,
        input_data.to_vec(),
        issuer_der.to_vec(),
        issuer_crl.map(|crl| crl.to_vec()),
    ).await?;

    Ok((
        image_id,
        journal,
        seal
    ))
}