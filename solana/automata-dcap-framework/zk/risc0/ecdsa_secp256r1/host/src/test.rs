use super::*;
use ecdsa_sepc256r1_methods::ECDSA_SEPC256R1_GUEST_ELF;
use risc0_zkvm::{ExecutorEnv, SessionInfo, compute_image_id, default_executor};

pub const ROOT_CRL_BYTES: &'static [u8] = include_bytes!("../sample/root_crl.der");

#[test]
pub fn test_image_id() {
    let image_id: [u8; 32] = compute_image_id(ECDSA_SEPC256R1_GUEST_ELF).unwrap().into();
    println!("image id: {:?}", image_id);
}

#[test]
pub fn test_verify_root_x509() {
    let root_der_bytes = include_bytes!("../sample/root.der");

    let serialized_input = serialize_input(
        InputType::X509,
        root_der_bytes.to_vec(),
        root_der_bytes.to_vec()
    )
    .unwrap();

    get_execution_session_info(serialized_input.as_slice());
}

#[test]
pub fn test_verify_root_crl() {
    let issuer_bytes = include_bytes!("../sample/root.der");

    let serialized_input = serialize_input(
        InputType::CRL,
        ROOT_CRL_BYTES.to_vec(),
        issuer_bytes.to_vec()
    )
    .unwrap();

    get_execution_session_info(serialized_input.as_slice());
}

// #[test]
// pub fn test_verify_tcb_info() {
//     let tcb_bytes = include_bytes!("../sample/tcb_info_v3_sgx.json");
//     let issuer_bytes = include_bytes!("../sample/signing.der");

//     let serialized_input = serialize_input(
//         InputType::TcbInfo,
//         tcb_bytes.to_vec(),
//         issuer_bytes.to_vec()
//     )
//     .unwrap();
//     get_execution_session_info(serialized_input.as_slice());
// }

// #[test]
// pub fn test_verify_qe_identity() {
//     let qe_identity_bytes = include_bytes!("../sample/qe_identity.json");
//     let issuer_bytes = include_bytes!("../sample/signing.der");

//     let serialized_input = serialize_input(
//         InputType::Identity,
//         qe_identity_bytes.to_vec(),
//         issuer_bytes.to_vec(),
//     )
//     .unwrap();
//     get_execution_session_info(serialized_input.as_slice());
// }

// For the simplicity of unit tests, we only test for the guest code to
// execute as expected, since we will be doing proof verification directly on-chain
fn get_execution_session_info(input: &[u8]) -> SessionInfo {
    let env = ExecutorEnv::builder().write_slice(input).build().unwrap();

    default_executor()
        .execute(env, ECDSA_SEPC256R1_GUEST_ELF)
        .unwrap()
}
