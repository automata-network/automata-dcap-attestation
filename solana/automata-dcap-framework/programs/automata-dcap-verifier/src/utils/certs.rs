use alloy_primitives::FixedBytes;
use alloy_sol_types::{SolType, SolValue, sol};
use anchor_lang::prelude::*;
use programs_shared::x509_parser::prelude::*;
use sha2::{Digest, Sha256};

use crate::errors::*;

type DerChainType = sol!(bytes[]);
type OutputType = (FixedBytes<32>, FixedBytes<32>, bool);

pub fn compute_output_digest_from_pem(pck_cert_chain_pem: &[u8]) -> Result<(Vec<Vec<u8>>, [u8; 32])> {
    let mut cert_chain: Vec<Vec<u8>> = Vec::new();

    for (i, pem) in Pem::iter_from_buffer(pck_cert_chain_pem).enumerate() {
        if i < 3 {
            let current_pem = pem.unwrap().contents;
            cert_chain.push(current_pem);
        } else {
            msg!("Certificate chain is too long");
            return Err(DcapVerifierError::SerializationError.into());
        }
    }

    // This creates another copy of the cert_chain but in encoded form
    let encoded_chain = DerChainType::abi_encode_params(&cert_chain);

    let encoded_hash = Sha256::digest(&encoded_chain);
    let root_hash = Sha256::digest(&cert_chain[cert_chain.len() - 1]);

    // make copies of encoded_hash and root_hash
    let output: OutputType = (
        FixedBytes::<32>::from_slice(encoded_hash.as_slice()),
        FixedBytes::<32>::from_slice(root_hash.as_slice()),
        true,
    );

    let output_hash = Sha256::digest(output.abi_encode_params().as_slice());

    Ok((cert_chain, output_hash.into()))
}