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

    let (_, issuer_der) = client
        .get_pcs_certificate(CertificateAuthority::PLATFORM, false)
        .await
        .unwrap();

    let (_image_id, _journal, proof) = request_ecdsa_verify_proof(
        EcdsaZkVerifyInputType::X509,
        pck_cert_data.as_slice(),
        issuer_der.as_slice(),
        Some(ROOT_CRL_BYTES)
    )
    .await
    .unwrap();

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
