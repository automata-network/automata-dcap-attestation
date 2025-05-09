use borsh::{BorshDeserialize, BorshSerialize};
use dcap_rs::types::{
    enclave_identity::QuotingEnclaveIdentityAndSignature, tcb_info::TcbInfoAndSignature,
};
use der::{Decode, Encode};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use risc0_zkvm::guest::env;
use sha2::{Digest, Sha256};
use std::io::Read;
use x509_cert::Certificate;
use x509_cert::crl::CertificateList;

#[derive(BorshDeserialize, BorshSerialize, PartialEq)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum InputType {
    X509 = 0,
    CRL = 1,
    TcbInfo = 2,
    Identity = 3,
}

#[derive(BorshDeserialize, BorshSerialize)]
struct Input {
    pub input_type: InputType,
    pub input_data: Vec<u8>,
    pub issuer_raw_der: Vec<u8>,
    /// This CRL is used to verify the revocation status of the issuer certificate
    /// It is optional because the RootCA certificate is irrevocable
    pub crl_raw_der: Option<Vec<u8>>
}

fn main() {
    // Read the input from the environment
    let mut input_bytes: Vec<u8> = vec![];
    env::stdin().read_to_end(&mut input_bytes).unwrap();

    // Deserialize the input
    let input = Input::try_from_slice(&input_bytes).unwrap();
    let issuer_cert = Certificate::from_der(&input.issuer_raw_der).unwrap();

    // First, we can check whether the issuer certificate has been revoked
    let crl_tbs_digest = if let Some(crl) = input.crl_raw_der {
        let issuer_serial_number = issuer_cert.tbs_certificate.serial_number.as_bytes();
        let crl_data = CertificateList::from_der(&crl).expect("Failed to parse CRL");
        let issuer_is_valid = check_certificate_revocation(
            issuer_serial_number, 
            &crl_data
        );
        assert!(issuer_is_valid, "Issuer certificate has been revoked");

        let crl_tbs = crl_data
            .tbs_cert_list
            .to_der()
            .expect("Failed to get CRL TBS");
        Sha256::digest(&crl_tbs).into()
    } else {
        [0u8; 32]
    };

    // extract pubkey from the issuer certificate
    let issuer_cert_pubkey_bytes = issuer_cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .unwrap();
    let issuer_cert_verifying_key =
        VerifyingKey::from_sec1_bytes(issuer_cert_pubkey_bytes).unwrap();

    let (fingerprint, tbs, sig) = match input.input_type {
        InputType::X509 => {
            // parse the X509 certificate
            let x509_cert =
                Certificate::from_der(&input.input_data).expect("Failed to parse X509 certificate");
            let tbs_der = x509_cert
                .tbs_certificate
                .to_der()
                .expect("Failed to get X509 TBS");
            let fingerprint: [u8; 32] = Sha256::digest(&input.input_data).into();
            let cert_sig = x509_cert.signature.as_bytes().unwrap();
            let sig = Signature::from_der(cert_sig).expect("Failed to parse X509 signature");
            (fingerprint, tbs_der, sig)
        },
        InputType::CRL => {
            // parse the CRL
            let crl = CertificateList::from_der(&input.input_data)
                .expect("Failed to parse CRL");
            let tbs_der = crl
                .tbs_cert_list
                .to_der()
                .expect("Failed to get CRL TBS");
            let fingerprint: [u8; 32] = Sha256::digest(&input.input_data).into();
            let crl_sig = crl.signature.as_bytes().unwrap();
            let sig = Signature::from_der(crl_sig).expect("Failed to parse CRL signature");
            (fingerprint, tbs_der, sig)
        }
        InputType::TcbInfo => {
            // parse the TCBInfo
            let tcb_info_json: TcbInfoAndSignature =
                serde_json::from_slice(&input.input_data).expect("Failed to parse TCBInfo");
            let tcb_info = tcb_info_json.get_tcb_info().expect("Failed to get TCBInfo");
            let tcb_info_serialized = tcb_info.to_borsh_bytes().expect("Failed to serialize TCBInfo");
            let fingerprint: [u8; 32] = Sha256::digest(&tcb_info_serialized).into();
            let sig = Signature::from_slice(tcb_info_json.signature.as_slice())
                .expect("Failed to parse TCBInfo signature");
            (
                fingerprint,
                tcb_info_json.tcb_info_raw.to_string().into_bytes(),
                sig,
            )
        },
        InputType::Identity => {
            // parse the Identity
            let identity_json: QuotingEnclaveIdentityAndSignature =
                serde_json::from_slice(&input.input_data).expect("Failed to parse Identity");
            let identity = identity_json
                .get_enclave_identity()
                .expect("Failed to get Identity");
            let identity_serialized = identity.to_borsh_bytes().expect("Failed to serialize Identity");
            let fingerprint: [u8; 32] = Sha256::digest(&identity_serialized).into();
            let sig = Signature::from_slice(identity_json.signature.as_slice())
                .expect("Failed to parse Identity signature");
            (
                fingerprint,
                identity_json.enclave_identity_raw.to_string().into_bytes(),
                sig,
            )
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

    let mut output = [0u8; 128];
    output[0..32].copy_from_slice(&fingerprint);
    output[32..64].copy_from_slice(&subject_tbs_hash);
    output[64..96].copy_from_slice(&issuer_tbs_hash);
    output[96..128].copy_from_slice(&crl_tbs_digest);

    // commit the output
    env::commit_slice(output.as_slice());
}

pub fn check_certificate_revocation(serial_number: &[u8], crl: &CertificateList) -> bool {
    if let Some(revoked_list) = crl.tbs_cert_list.revoked_certificates.as_ref() {
        for revoked_cert in revoked_list {
            let revoked_serial_number_bytes = revoked_cert.serial_number.as_bytes();
            if revoked_serial_number_bytes == serial_number {
                return false;
            }
        }
    }

    true
}