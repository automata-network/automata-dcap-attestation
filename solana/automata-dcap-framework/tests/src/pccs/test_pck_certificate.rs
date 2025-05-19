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
    // )
    // .await
    // .unwrap();

    let proof = hex::decode("216cd5a0ba2000f9fdad05d70aa9edf7944af286c85c884ba0aff3608e81302d09f865aa3b8c30b970bd3dbd652e408057a2df1110cdc3db32f8b5a00e6cc6fa0168b1649237d5fe65155092b1c2592cc19afa0040130a399975d537ec4f3d4f295c538afe946265b6c1e77d7705a447c9bbd75384265d759bde369c88b5a2a9265ddf88e397b67ba59beec56c8b88e6b6a7a3ad899c06c80cd2d9ba004409b62b3512a66a070957f4444ae6f7082065910a3f8f5996363c0137a2ffb1a9d9f501b50d89e0ddf774eb39f3484a564a117783fbb60a9f8e2c1f227edebf2c9be20a681c6b379e14fc48860929127de2d4f7961f99afb7bd595c949fa25a40e58a").unwrap();

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
