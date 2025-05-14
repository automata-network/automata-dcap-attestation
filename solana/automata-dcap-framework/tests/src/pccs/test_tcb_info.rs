use anchor_client::solana_sdk::signer::keypair::Keypair;
use dcap_rs::types::tcb_info::{TcbInfoAndSignature, TcbInfoVersion};
use sdk::Sdk;
use sdk::models::{CertificateAuthority, TcbType};
use sdk::pccs::automata_on_chain_pccs::types::ZkvmSelector;
use sdk::pccs::{EcdsaZkVerifyInputType, request_ecdsa_verify_proof};
use std::str::FromStr;
use std::sync::Arc;

use crate::{ROOT_CRL_BYTES, TEST_RISC0_VERIFIER_PUBKEY};

pub(crate) async fn test_tcb_info_upsert_v3_sgx(sdk: &Sdk<Arc<Keypair>>) {
    let tcb_info_data = include_bytes!("../../data/tcb_info_v3_sgx.json");

    let tcb_info_and_signature: TcbInfoAndSignature =
        serde_json::from_slice(tcb_info_data).unwrap();
    let tcb_info_parsed = tcb_info_and_signature.get_tcb_info().unwrap();

    let client = sdk.pccs_client();
    let data_buffer_pubkey = client
        .upload_tcb_data(tcb_info_data.as_slice(), None)
        .await
        .unwrap();

    let (_, issuer_der) = client
        .get_pcs_certificate(CertificateAuthority::SIGNING, false)
        .await
        .unwrap();

    let (_image_id, _journal, proof) = request_ecdsa_verify_proof(
        EcdsaZkVerifyInputType::TcbInfo,
        tcb_info_data.as_slice(),
        issuer_der.as_slice()
    )
    .await
    .unwrap();

    let tcb_type = TcbType::Sgx;
    let fmspc = "00A067110000";
    let fmspc_bytes: [u8; 6] = hex::decode(fmspc).unwrap().try_into().unwrap();
    let _tx = client
        .upsert_tcb_info(
            data_buffer_pubkey,
            TEST_RISC0_VERIFIER_PUBKEY,
            tcb_type,
            3,
            fmspc_bytes,
            ZkvmSelector::RiscZero,
            proof,
        )
        .await
        .unwrap();

    let (_, tcb_info) = client.get_tcb_info(tcb_type, fmspc_bytes, 3).await.unwrap();
    assert_eq!(&tcb_info_parsed, &tcb_info);

    let tcb_type_string = tcb_info.id.unwrap_or_else(|| "SGX".to_string());
    let actual_tcb_type: TcbType = TcbType::from_str(&tcb_type_string).unwrap();

    assert_eq!(tcb_info.version, TcbInfoVersion::V3);
    assert_eq!(actual_tcb_type, tcb_type);
    assert_eq!(tcb_info.fmspc, fmspc_bytes);
}

pub(crate) async fn test_tcb_info_upsert_v3_tdx(sdk: &Sdk<Arc<Keypair>>) {
    let tcb_info_data = include_bytes!("../../data/tcb_info_v3_with_tdx_module.json");

    let tcb_info_and_signature: TcbInfoAndSignature =
        serde_json::from_slice(tcb_info_data).unwrap();
    let tcb_info_parsed = tcb_info_and_signature.get_tcb_info().unwrap();

    let client = sdk.pccs_client();
    let data_buffer_pubkey = client
        .upload_tcb_data(tcb_info_data.as_slice(), None)
        .await
        .unwrap();

    // let (_, issuer_der) = client
    //     .get_pcs_certificate(CertificateAuthority::SIGNING, false)
    //     .await
    //     .unwrap();

    // let (_image_id, _journal, proof) = request_ecdsa_verify_proof(
    //     EcdsaZkVerifyInputType::TcbInfo,
    //     tcb_info_data.as_slice(),
    //     issuer_der.as_slice(),
    // )
    // .await
    // .unwrap();

    let proof = hex::decode("1a08a2ad0d73fe85f63853171ec62a9604f47c9470f769e2abfec21f09ae2bae0606254c072488a8ae36c6663b7df52fc5d9a59887e83e0c91985b15579fc0202166177583db12c1b34be6078b7e91a0715e41322a638a17b66c7b6dbd82e68b1de93d413e96571dfd2622c9f26c09e259f24b674fa356bb265a4c50fdb3fb7014546e7a8451c0c454b45106ffb0aa989b47f2e42bda8debbf544ad4eb2c872e195f2172191496e563c763651b8fec4aabb1f4033e8b9fa5676903bf8ce2fc4b1b593226fbbf025745da2a999a5d6d0ab84d4fead1a6830935d63bce36a21a92092f579139870d0dfcd750b43339e46b28927c3e159e0047fe9c95cd45b5dc93").unwrap();

    let tcb_type = TcbType::Tdx;
    let fmspc = "00806f050000";
    let fmspc_bytes: [u8; 6] = hex::decode(fmspc).unwrap().try_into().unwrap();
    let _tx = client
        .upsert_tcb_info(
            data_buffer_pubkey,
            TEST_RISC0_VERIFIER_PUBKEY,
            tcb_type,
            3,
            fmspc_bytes,
            ZkvmSelector::RiscZero,
            proof,
        )
        .await
        .unwrap();

    let (_, tcb_info) = client.get_tcb_info(tcb_type, fmspc_bytes, 3).await.unwrap();
    assert_eq!(&tcb_info_parsed, &tcb_info);

    let tcb_type_string = tcb_info.id.unwrap_or_else(|| "SGX".to_string());
    let actual_tcb_type: TcbType = TcbType::from_str(&tcb_type_string).unwrap();

    assert_eq!(tcb_info.version, TcbInfoVersion::V3);
    assert_eq!(actual_tcb_type, tcb_type);
    assert_eq!(tcb_info.fmspc, fmspc_bytes);
}
