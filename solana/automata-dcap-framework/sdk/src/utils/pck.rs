use anyhow::Result;
use zk_x509_client::prove_der_chain;

pub fn verify_pck_chain_zk(
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

    let (image_id, journal_bytes, groth16_seal) = prove_der_chain(cert_chain)?;
    Ok((image_id, journal_bytes, groth16_seal))
}
