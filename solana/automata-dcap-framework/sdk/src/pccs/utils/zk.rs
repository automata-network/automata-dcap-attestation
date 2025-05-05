use anyhow::Result;
use ecdsa_secp256r1_host::{InputType, verify_non_blocking};

/// We use the ecdsa guest program here instead becasue
/// we are not verifying the entire chain
/// the ecdsa guest program can also be used to verify JSON collaterals

pub async fn get_x509_ecdsa_verify_proof(
    subject_der: &[u8],
    issuer_der: &[u8]
) -> Result<(
    [u8; 32], // image_id
    Vec<u8>,  // journal_bytes
    Vec<u8>,  // Groth16 Seal
)> {
    let (image_id, journal, seal) = verify_non_blocking(
        InputType::X509,
        subject_der.to_vec(),
        issuer_der.to_vec()
    ).await?;

    Ok((
        image_id,
        journal,
        seal
    ))
}

/// Call this method for JSON collaterals
pub async fn get_json_ecdsa_verify_proof(
    input_type: InputType,
    input_data: &[u8],
    issuer_der: &[u8]
) -> Result<(
    [u8; 32], // image_id
    Vec<u8>,  // journal_bytes
    Vec<u8>,  // Groth16 Seal
)> {

    assert!(input_type != InputType::X509, "Use get_x509_ecdsa_verify_proof for X509 collaterals");

    let (image_id, journal, seal) = verify_non_blocking(
        input_type,
        input_data.to_vec(),
        issuer_der.to_vec()
    ).await?;

    Ok((
        image_id,
        journal,
        seal
    ))
}