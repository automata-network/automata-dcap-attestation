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

    let proof = hex::decode("2b72341f368f07d7e5f0094bbaa9cd4ae5747593e8c4cf2dd6f2f853e364df632c0d6116377093718deccd755806f9f1aeff7bc3b9deda0375f74b01ca7daccc2bda769aaaedb0306b9e393600694f52d45779cc90fd3c84a306f07e200dcf7200206d20f39ff5abec8973b70b00ad67b8f8d79be35e75267bda259b605e18ea07a39f2d3c970cb65373157d70ad4ad19b877789b6922e0456f75f249a4d1c37025ea73cd79631d83a3777f3133984752bcba8d754350ef4c0969483602c03a11f906c18a044dc0ee525f835fd101e388da8ecfca190e1c40ad0be53255ba45216b82c98d58e0c94daca774d56ed23504b026d6533f2a67bd6c378e20f9bc2f9").unwrap();

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
