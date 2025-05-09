use anyhow::Result;
use zk_x509_client::prove_der_chain_non_blocking;

pub async fn verify_pck_chain_zk(
    pck_cert_chain_pem: &[u8],
) -> Result<(
    [u8; 32], // image_id
    Vec<u8>,  // journal_bytes
    Vec<u8>,  // Groth16 Seal
)> {
    let cert_chain: Vec<Vec<u8>> = pem::parse_many(pck_cert_chain_pem)
        .unwrap()
        .iter()
        .map(|pem| pem.contents().to_vec())
        .collect();

    let (image_id, journal_bytes, mut groth16_seal) = prove_der_chain_non_blocking(
        cert_chain, 
        false
    ).await?;

    // negate risczero pi_a
    let mut pi_a: [u8; 64] = [0; 64];
    pi_a.copy_from_slice(&groth16_seal[0..64]);

    let negated_pi_a = crate::shared::negate_g1(&pi_a);
    groth16_seal[0..64].copy_from_slice(&negated_pi_a);

    println!("proof: {}", hex::encode(&groth16_seal));

    Ok((image_id, journal_bytes, groth16_seal))
}
