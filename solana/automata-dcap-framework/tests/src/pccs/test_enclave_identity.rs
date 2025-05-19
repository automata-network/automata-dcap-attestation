use std::sync::Arc;
use sdk::Sdk;
use sdk::models::{EnclaveIdentityType, CertificateAuthority};
use sdk::pccs::automata_on_chain_pccs::types::ZkvmSelector;
use sdk::pccs::{EcdsaZkVerifyInputType, request_ecdsa_verify_proof};
use anchor_client::solana_sdk::signer::keypair::Keypair;
use crate::TEST_RISC0_VERIFIER_PUBKEY;
use dcap_rs::types::enclave_identity::{EnclaveType, QuotingEnclaveIdentityAndSignature};

pub(crate) async fn test_enclave_identity_upsert(sdk: &Sdk<Arc<Keypair>>) {
    let enclave_identity_data = include_bytes!("../../data/qe_identity.json").to_vec();
    let enclave_identity_and_signature: QuotingEnclaveIdentityAndSignature =
        serde_json::from_slice(&enclave_identity_data).unwrap();
    let enclave_identity_parsed = enclave_identity_and_signature.get_enclave_identity().unwrap();

    let client = sdk.pccs_client();
    let data_buffer_pubkey = client.upload_identity_data(
        enclave_identity_data.as_slice(),
        None
    ).await.unwrap();

    // let (_, issuer_der) = client
    //     .get_pcs_certificate(CertificateAuthority::SIGNING, false)
    //     .await
    //     .unwrap();

    // let enclave_identity_on_chain_data = client.load_buffer_data(data_buffer_pubkey).await.unwrap();
    // let (_image_id, _journal, proof) = request_ecdsa_verify_proof(
    //     EcdsaZkVerifyInputType::Identity,
    //     &enclave_identity_on_chain_data.as_slice(),
    //     issuer_der.as_slice()
    // )
    // .await
    // .unwrap();

    let proof = hex::decode("17106361db61bc80e9c003279edb72bd02c28aff86a74ca910ac3aa7ace7f8292c99c0ba9a296c3693902a9d230fb77a1a0e49885802e317751e06280c23bf4e1a35134b0442f94015093e83d21782d788c99f9a4548110948f33e2efaf497fe04bd16fdb1e0b393a2faf73b2b8f968e55da8defad284c132256040217948a350fe860fff49ef8c0f4fa0705e6b2728a9a6f6eabfd28683cdeb399909811e1701bf4bd19a5bb2022c1d646f40eb227ff985290f7eb3eea1cb2fdd822cddea2be0ebc640c2779334ae299ae4b8b8dd0ee985437ddc5a1819d1bccdb9497ac90f42fb83c8c81f9a62104ed3da5d36f861479b4bf0b55a93e7c054f1aa0cb9e875e").unwrap();

    let _tx = client.upsert_enclave_identity(
        data_buffer_pubkey,
        TEST_RISC0_VERIFIER_PUBKEY,
        EnclaveIdentityType::TdQe,
        2,
        ZkvmSelector::RiscZero,
        proof
    ).await.unwrap();

    let (_, enclave_identity) = client.get_enclave_identity(
        EnclaveIdentityType::TdQe,
        2,
    ).await.unwrap();
    assert_eq!(&enclave_identity_parsed, &enclave_identity);

    let actual_identity_type = enclave_identity.id;
    let expected_identity_type = EnclaveType::TdQe;
    assert_eq!(actual_identity_type, expected_identity_type);
    assert_eq!(enclave_identity.version, 2);
}
