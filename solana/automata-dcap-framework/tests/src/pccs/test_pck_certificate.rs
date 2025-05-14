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

    let proof = hex::decode("2244136ea229599cb9d025158fac4b4a3585bb334382c392ebcd4ba4408a35ae1f667a0a53c5751f9f6dedd0e3ec4064713c339b4476829faebe6772e74a33e1291176c655dadf1bae03b698782648d8b183b2d4f323e67f53daa3006f6715b1214b280b2f3d06539098fc019fde8859e36849989c82267a74cc860036abfd1b05285a8f7c0463f2be33e9718f36e41e4d19de5f10f8bbe86b3bc5de7eb020cc2a53ec3147dc4d4ec3347bc2246d2e9fbfd210c775c8282a784fe8663c24dbb60756519c04c141ffb8c7e8f20b02bdb20b7f5f084e02e4307d2cc2251579a24d291ee2c13f114e7337d4b68b1a790606bf137c7c1ffdb5044e626eafa218494a").unwrap();

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
