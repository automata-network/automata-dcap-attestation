use std::sync::Arc;
use sdk::Sdk;
use sdk::pccs::automata_on_chain_pccs::types::ZkvmSelector;
use sdk::models::CertificateAuthority;
use sdk::pccs::{EcdsaZkVerifyInputType, request_ecdsa_verify_proof};
use anchor_client::solana_sdk::signer::keypair::Keypair;
use crate::{ROOT_CRL_BYTES, TEST_RISC0_VERIFIER_PUBKEY};

pub(crate) async fn test_pck_certificate_upsert(sdk: &Sdk<Arc<Keypair>>) {
    let pck_cert_data = include_bytes!("../../data/pck.der").to_vec();

    let client = sdk.pccs_client();
    let data_buffer_pubkey = client.upload_pck_data(
        pck_cert_data.as_slice(), 
        None
    ).await.unwrap();

    // let (_, issuer_der) = client
    //     .get_pcs_certificate(CertificateAuthority::PLATFORM, false)
    //     .await
    //     .unwrap();

    // let (_image_id, _journal, proof) = request_ecdsa_verify_proof(
    //     EcdsaZkVerifyInputType::X509,
    //     pck_cert_data.as_slice(),
    //     issuer_der.as_slice(),
    //     Some(ROOT_CRL_BYTES)
    // )
    // .await
    // .unwrap();

    let proof = hex::decode("0958d50573d1839847fafb9b2337e0ae014e1253f38d581d373a710613c0c5ab00aa79581dd0b72896c1a49f386b6adb962aeafa8a6cc5660962f2b7df7111290324cfd910f0e2d62fc784b4fd5c63f7fdffc4551500312368f48a6e090a5f92225576c973ae57f7eae994de2e317555ee4b235377570027adbf68fa7f6ee8ad185002dce5e112470f6ff124a614fa950ad0b287cf3e5aa4802146313f6903ab1592232127a816b525b079f31e91a5f3219bbac1d93f606d998a568b69347ba600edfc999fa2514044f3a891b48f8c8e1822c5c0155595b5f8114932b2dbd6451e89f5d72b23fcc3591d2be6274c6a1c48f41ad202094b52545629fe1e34c123").unwrap();

    let qe_id = "ad04024c9dfb382baf51ca3e5d6cb6e6";
    let pce_id = "0000";
    let tcbm = "0c0c0303ffff010000000000000000000d00";

    let _tx = client.upsert_pck_certificate(
        data_buffer_pubkey,
        TEST_RISC0_VERIFIER_PUBKEY,
        qe_id.to_string(),
        pce_id.to_string(),
        tcbm.to_string(),
        ZkvmSelector::RiscZero,
        proof
    ).await.unwrap();

    let (_, pck_cert) = client.get_pck_certificate(
        qe_id.to_string(),
        pce_id.to_string(),
        tcbm.to_string(),
   ).await.unwrap();

   assert_eq!(pck_cert, pck_cert_data);
}
