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

    let proof = hex::decode("2fd9e1dd1d3cdd41728c311eef969e52241dccaf75c83ff9bdc1d5019cc4bbec25937b3ae581d867376db9c5840a8169950f380cdebd9cb2fda9634c259f09be2f1ba2452d6706de8028a14934198f0fdd369b6116b1a4d557bc22840784267b05cff23abeacf2cf749fca857f94b5fd15a6ff6921e84dc2bc73efce869e16000201672753d35332d7be9d8c26cd949f20d14b48782c248787dc9f64eeb342be09357084c02a394a7f29647769b3f83d58700b7ee46fb4c47b69554039d3348b0b3f9adf152a0f3420592a0fc3ca65f357a5243ddbaf3b48fbd3e181de81e2e1030964eaf7fcf43044dfb6db51042f1460077d303842f442dfb8831f5a98ed1b").unwrap();

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
