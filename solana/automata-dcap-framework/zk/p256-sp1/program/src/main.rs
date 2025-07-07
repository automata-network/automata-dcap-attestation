// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use borsh::BorshDeserialize;
use dcap_rs::types::pod::enclave_identity::serialize::parse_enclave_identity_pod_bytes;
use dcap_rs::types::pod::tcb_info::serialize::parse_tcb_pod_bytes;
use der::{Decode, Encode};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use sha2::{Digest, Sha256};
use x509_cert::Certificate;
use x509_cert::crl::CertificateList;

use dcap_p256_zk_lib::*;

pub fn main() {
    // Read the input from the environment
    let input_bytes: Vec<u8> = sp1_zkvm::io::read_vec();

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

    let fingerprint: [u8; 32] = Sha256::digest(&input.subject_data).into();

    let (tbs, sig) = match input.input_type {
        InputType::X509 => {
            // parse the X509 certificate
            let x509_cert = Certificate::from_der(&input.subject_data)
                .expect("Failed to parse X509 certificate");
            let tbs_der = x509_cert
                .tbs_certificate
                .to_der()
                .expect("Failed to get X509 TBS");
            let cert_sig = x509_cert.signature.as_bytes().unwrap();
            let sig = Signature::from_der(cert_sig).expect("Failed to parse X509 signature");
            (tbs_der, sig)
        },
        InputType::CRL => {
            // parse the CRL
            let crl = CertificateList::from_der(&input.subject_data).expect("Failed to parse CRL");
            let tbs_der = crl.tbs_cert_list.to_der().expect("Failed to get CRL TBS");
            let crl_sig = crl.signature.as_bytes().unwrap();
            let sig = Signature::from_der(crl_sig).expect("Failed to parse CRL signature");
            (tbs_der, sig)
        },
        InputType::TcbInfo => {
            let clone = input.subject_data.clone(); // clone the subject data to mitigate alignment issues
            // parse the TCBInfo
            let (tcb_info, sig) =
                parse_tcb_pod_bytes(clone.as_slice()).expect("Failed to parse TCB info");

            let tcb_info_tbs = serde_json::to_string(&tcb_info)
                .expect("Failed to serialize TCB info into JSON string")
                .as_bytes()
                .to_vec();

            let sig = Signature::from_slice(&sig).expect("Failed to parse TCBInfo signature");

            (tcb_info_tbs, sig)
        },
        InputType::Identity => {
            let clone = input.subject_data.clone(); // clone the subject data to mitigate alignment issues
            // parse the Identity
            let (identity, sig) = parse_enclave_identity_pod_bytes(clone.as_slice())
                .expect("Failed to parse Identity");

            let identity_tbs = serde_json::to_string(&identity)
                .expect("Failed to serialize Identity into JSON string")
                .as_bytes()
                .to_vec();

            let sig = Signature::from_slice(&sig).expect("Failed to parse Identity signature");

            (identity_tbs, sig)
        },
    };

    // verify the signature
    let verified = issuer_cert_verifying_key.verify(&tbs, &sig).is_ok();
    assert!(verified, "Signature verification failed");

    // generate the output
    // the output is a 128-byte data consists of
    // - SHA256 fingerprint of the data stored onchain
    //  - For X509 certificates, it is the SHA256 hash of the entire X509 Certificate data encoded in DER format
    //  - For TCBInfo, it is the SHA256 hash of the Borsh serialized TCBInfo
    //  - For Identity, it is the SHA256 hash of the Borsh serialized Identity Body
    // - SHA256 hash of the data that is signed
    // - SHA256 hash of the issuer certificate tbs
    // - SHA256 hash of the issuer CRL tbs (if any, otherwise it contains 32 bytes of 0s)
    let subject_tbs_hash: [u8; 32] = Sha256::digest(&tbs).into();

    let issuer_tbs_hash: [u8; 32] =
        Sha256::digest(&issuer_cert.tbs_certificate.to_der().unwrap()).into();

    let mut output = [0u8; 96];
    output[0..32].copy_from_slice(&fingerprint);
    output[32..64].copy_from_slice(&subject_tbs_hash);
    output[64..96].copy_from_slice(&issuer_tbs_hash);

    // commit the output
    sp1_zkvm::io::commit_slice(output.as_slice());
}
