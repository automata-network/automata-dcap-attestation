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

    let proof = hex::decode("1af2c7a271632660b897ce915bf0a7ad30c94c18afa3ada2ca9f84fabc4fe14d1cf236af908303fd69e79c101042c1edb9c16955a4e0d48f1f13a616b873c90f07a15c8481fbc45e544b7e05051597db140e3912e8b1ded402775f163c8622f01c2c618eeee1f4bc58f31ddeb5e8ea3a729b234f390802d2f8f841fe1428e48a0a3ec1308944893885025565a9efa2d3725bc76e42f6b01327da703fd9d5a531204eed453b3cfe032ae4f20fe7fd78398f960cdb06d6ccb8f668cba1642aee4c01cca7bd8740dfaa4e6d6d7a9925fdea8ac2039d75b1944ba9da741f5f1d0e161e351efe9b40440d4172d0b5d017799cdc78dd0addc1ebf1c046c6e0050ad683").unwrap();

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
