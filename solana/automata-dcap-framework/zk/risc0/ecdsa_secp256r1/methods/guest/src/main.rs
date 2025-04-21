use risc0_zkvm::guest::env;
use std::io::Read;
use borsh::{BorshDeserialize, BorshSerialize};
use der::{Encode, Decode};
use x509_cert::Certificate;
use p256::ecdsa::{
    Signature,
    VerifyingKey,
    signature::hazmat::PrehashVerifier,
};
use sha2::{Sha256, Digest};

#[derive(BorshDeserialize, BorshSerialize)]
struct Input {
    pub input_digest: [u8; 32],
    pub input_signature: [u8; 64],
    pub issuer_raw_der: Vec<u8>
}

fn main() {
    // Read the input from the environment
    let mut input_bytes: Vec<u8> = vec![];
    env::stdin().read_to_end(&mut input_bytes).unwrap();

    // Deserialize the input
    let input = Input::try_from_slice(&input_bytes).unwrap();
    let issuer_cert = Certificate::from_der(&input.issuer_raw_der).unwrap();

    // extract pubkey from the issuer certificate
    let issuer_cert_pubkey_bytes = issuer_cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .unwrap();
    let issuer_cert_verifying_key =
        VerifyingKey::from_sec1_bytes(issuer_cert_pubkey_bytes).unwrap();

    // get signature
    let signature = Signature::from_slice(&input.input_signature).unwrap();

    // verify signature
    let verified = issuer_cert_verifying_key
        .verify_prehash(&input.input_digest, &signature)
        .is_ok();

    assert!(verified, "Signature verification failed");

    // generate the output
    // the output is a 64-byte data consists of 
    // - 32-byte digest
    // - SHA256 hash of the issuer certificate tbs

    let issuer_tbs_hash: [u8; 32] = Sha256::digest(
        &issuer_cert.tbs_certificate
            .to_der()
            .unwrap()
    ).into();

    let mut output = [0u8; 64];
    output[..32].copy_from_slice(&input.input_digest);
    output[32..].copy_from_slice(&issuer_tbs_hash);

    // commit the output
    env::commit_slice(output.as_slice());
}
