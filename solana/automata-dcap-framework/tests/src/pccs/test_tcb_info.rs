use anchor_client::solana_sdk::signer::keypair::Keypair;
use dcap_rs::types::tcb_info::{TcbInfoAndSignature, TcbInfoVersion};
use sdk::Sdk;
use sdk::models::{CertificateAuthority, TcbType};
use sdk::pccs::automata_on_chain_pccs::{types::ZkvmSelector, accounts::TcbInfo as TcbInfoAccount};
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

    let data_buffer_account_data = client.load_buffer_data(data_buffer_pubkey).await.unwrap();

    let (_, issuer_der) = client
        .get_pcs_certificate(CertificateAuthority::SIGNING, false)
        .await
        .unwrap();

    let (_image_id, _journal, proof) = request_ecdsa_verify_proof(
        EcdsaZkVerifyInputType::TcbInfo,
        data_buffer_account_data.as_slice(),
        issuer_der.as_slice(),
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
    assert_eq!(tcb_info.fmspc, fmspc);
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

    let data_buffer_account_data = client.load_buffer_data(data_buffer_pubkey).await.unwrap();

    // let (_, issuer_der) = client
    //     .get_pcs_certificate(CertificateAuthority::SIGNING, false)
    //     .await
    //     .unwrap();

    // let (_image_id, _journal, proof) = request_ecdsa_verify_proof(
    //     EcdsaZkVerifyInputType::TcbInfo,
    //     data_buffer_account_data.as_slice(),
    //     issuer_der.as_slice(),
    // )
    // .await
    // .unwrap();

    let proof = hex::decode("04f1521bd97c7e91b7d31448b6a74c6d5648695575590dd3aaacd45b1bde3ea501e5713d020cdc15230161aebeabf15ca275107d7d9d29d37fc0f4a13aa3d17900e1ab779aa36a17e9c099d1c15ffa782f2afb2303dbf9d8fe8b7c6908074b291653a85b05bf20fe0aeda22375339915716a439d7749dc44b26654a0e637d0e208c5f541dc8f12f7a537d6fd2cc7220f9a82742bead9c8f0dbb56f46c2ff499f150b13d0f1aebcfaba1a0592c2464956866b05593f1a1235d41d261018f45755121603ea2815af73dc0d9296fa77655126bc44526de2b7ce73afbc4d8b9377620fe7d65068ffc8965121bec30325f645d9d1a2d5ba06714fa32fe7ca7b77359a").unwrap();

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
    assert_eq!(tcb_info.fmspc, fmspc);
}
