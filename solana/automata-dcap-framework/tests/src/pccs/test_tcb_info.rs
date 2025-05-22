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

    // let data_buffer_account_data = client.load_buffer_data(data_buffer_pubkey).await.unwrap();

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

    let proof = hex::decode("259659e72b79a5882d32e18644f417e0066350d21f9651c46d39ec51db75daea04fc5ebb356e37f2a5650aeaecc3cb985dc0446977c8f3180e1b7db9e064da412f9b9fc319ea66e16b0768b2a3d36635b2d7e34a534a94e8f2114ac017d640ca17f472a2fd4cadf9463c7ad42d4f745eb2f403077e3c9419bdcbd76136a9f6112867d9b26705719bac41c7647046c00e2f6a7b707b6db2aa98c20b59e98f1ff01b1319b7da34bf87784266bc7811646650440149cbe4ea054dcf75a06b0141df041c168c6e9e1133c87f9a3be33ecc0234f2ba11c34f07182f1132c75d24e4541c2a449825d5f2e7d06f37667ff013f5ed5ec556967342e8177e49a13b40f17f").unwrap();

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
