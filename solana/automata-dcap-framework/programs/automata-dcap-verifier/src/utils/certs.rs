use alloy_primitives::FixedBytes;
use alloy_sol_types::{SolType, SolValue, sol};
use sha2::{Digest, Sha256};

type DerChainType = sol!(bytes[]);
type OutputType = (FixedBytes<32>, FixedBytes<32>, bool);

pub fn compute_output_digest_from_pem(pck_cert_chain_pem: &[u8]) -> [u8; 32] {
    // After this call, it should immediately drop pem.content() value from memory per iteration
    // each content has been copied to the cert_chain vec
    let cert_chain: Vec<Vec<u8>> = pem::parse_many(pck_cert_chain_pem)
        .unwrap()
        .iter()
        .map(|pem| pem.contents().to_vec())
        .collect();

    // This creates another copy of the cert_chain but in encoded form
    let encoded_chain = DerChainType::abi_encode_params(&cert_chain);

    let encoded_hash = Sha256::digest(&encoded_chain);
    let root_hash = Sha256::digest(&cert_chain[cert_chain.len() - 1]);

    // free the memory allocated for the cert_chain
    drop(cert_chain);

    // make copies of encoded_hash and root_hash
    let output: OutputType = (
        FixedBytes::<32>::from_slice(encoded_hash.as_slice()),
        FixedBytes::<32>::from_slice(root_hash.as_slice()),
        true,
    );

    drop(encoded_chain);
    let _ = encoded_hash;
    let _ = root_hash;

    let output_hash = Sha256::digest(output.abi_encode_params().as_slice());

    output_hash.into()
}