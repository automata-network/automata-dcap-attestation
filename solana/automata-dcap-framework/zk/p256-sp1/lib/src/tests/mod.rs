use super::*;
use dcap_rs::types::pod::{enclave_identity::serialize::*, tcb_info::serialize::*};
use dcap_rs::types::{
    enclave_identity::QuotingEnclaveIdentityAndSignature, tcb_info::TcbInfoAndSignature,
};

#[test]
#[ignore]
pub fn test_zk_get_program_vkey() {
    // [0, 111, 202, 109, 191, 166, 239, 42, 224, 146, 249, 26, 3, 212, 159, 255, 220, 251, 19, 62, 72, 240, 105, 251, 148, 90, 95, 152, 48, 11, 41, 149]
    let vkey = get_program_vkey();
    println!("program vkey: {:?}", vkey);
}

#[test]
#[ignore]
pub fn test_zk_verify_root_x509() {
    let root_der_bytes = include_bytes!("./samples/root.der");

    let ret = get_proof(
        ProofType::Mock,
        InputType::X509,
        root_der_bytes.to_vec(),
        root_der_bytes.to_vec(),
    );

    assert!(ret.is_ok());
}

#[test]
#[ignore]
pub fn test_zk_verify_signing_x509() {
    let signing_der_bytes = include_bytes!("./samples/signing.der");
    let root_der_bytes = include_bytes!("./samples/root.der");

    assert!(
        get_proof(
            ProofType::Mock,
            InputType::X509,
            signing_der_bytes.to_vec(),
            root_der_bytes.to_vec()
        )
        .is_ok()
    );
}

#[test]
#[ignore]
pub fn test_zk_verify_root_crl() {
    let root_crl_bytes = include_bytes!("./samples/root_crl.der");
    let root_der_bytes = include_bytes!("./samples/root.der");

    assert!(
        get_proof(
            ProofType::Mock,
            InputType::CRL,
            root_crl_bytes.to_vec(),
            root_der_bytes.to_vec()
        )
        .is_ok()
    );
}

#[test]
#[ignore]
pub fn test_zk_verify_tcb_info() {
    let tcb_info_bytes = include_bytes!("./samples/tcb_info_v3_sgx.json");

    // serialize tcb_info into pod
    let tcb_info: TcbInfoAndSignature = serde_json::from_slice(tcb_info_bytes).unwrap();
    let tcb_info_body = tcb_info.get_tcb_info().unwrap();
    let tcb_info_pod = SerializedTcbInfo::from_rust_tcb_info(&tcb_info_body).unwrap();
    let mut tcb_info_signature: [u8; 64] = [0; 64];
    tcb_info_signature.copy_from_slice(&tcb_info.signature);
    let tcb_info_data = serialize_tcb_pod(&tcb_info_pod, &tcb_info_signature);

    let issuer_bytes = include_bytes!("./samples/signing.der");

    assert!(
        get_proof(
            ProofType::Mock,
            InputType::TcbInfo,
            tcb_info_data,
            issuer_bytes.to_vec()
        )
        .is_ok()
    );
}

#[test]
#[ignore]
pub fn test_zk_verify_enclave_identity() {
    let qe_identity_bytes = include_bytes!("./samples/qe_identity.json");

    // serialize enclave identity into pod
    let qe_identity: QuotingEnclaveIdentityAndSignature =
        serde_json::from_slice(qe_identity_bytes).unwrap();
    let qe_identity_body = qe_identity.get_enclave_identity().unwrap();
    let qe_identity_pod =
        SerializedEnclaveIdentity::from_rust_enclave_identity(&qe_identity_body).unwrap();
    let mut qe_identity_signature: [u8; 64] = [0; 64];
    qe_identity_signature.copy_from_slice(&qe_identity.signature);
    let qe_identity_data = serialize_enclave_identity_pod(&qe_identity_pod, &qe_identity_signature);

    let issuer_bytes = include_bytes!("./samples/signing.der");

    assert!(
        get_proof(
            ProofType::Mock,
            InputType::Identity,
            qe_identity_data,
            issuer_bytes.to_vec()
        )
        .is_ok()
    );
}
