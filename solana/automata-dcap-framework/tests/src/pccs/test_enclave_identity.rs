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

    let proof = hex::decode("24d98c10e47e478dc1f7eb143d1da9514b7299411edf1d3dd59257eadb7b4b2d0bdec3a219eb9b3f3ccabb4c90cb61c6da6d115f1f687a40daa523b32f590f5a13f3273a9e2a023e46f410a49698c515d719393e13609fdf270b5f2c3293ffe21b1fc3ec11fb69900fb97fd0372e5401a1df6d4dfd44fd18e1863d73e548b4d31b607353e5eb63dab784a65f59c10291c0519ec3b51bf9b9332ae54361099f5827a06d81a3d21786149d0e8631e225edfce6c0f9ceb44e02401d2d87615ba7d206b6f92fc1c5721fd664851777112a5adc0d8306d44b198f92d14da7781ec6320a95f966e446727bb6512ea6e0b4f02bf3dc74be2484df6d7a25ef57880adf5a").unwrap();

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
