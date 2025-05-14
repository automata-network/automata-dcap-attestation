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

    // let (_image_id, _journal, proof) = request_ecdsa_verify_proof(
    //     EcdsaZkVerifyInputType::Identity,
    //     enclave_identity_data.as_slice(),
    //     issuer_der.as_slice()
    // )
    // .await
    // .unwrap();

    let proof = hex::decode("06e86b337767b0c5996e6d46e8941303bbb6ba83f20c84c02d9c98833cc438ef29f43b70240862c816e79cca73922eb13faa5ac052be7176dc8b6371433426cf0c7942d9f5b6655d15776ce79a04f40b09c25fe5cdf264d3b2f6e3761e8a42e500f47b10909d6d733049972a2764ce7857e95aada42d0fe67927e261b6d4bbab10077169eea779e8b071d0224feccadee783d0b46f12689ea51b60dda5f6bf3e130a4a1e678ea721ecb1d38028027b30ddbf9add59a7c876023cd0488a2cde491b6ca906d87fd0ee523b13d9303c94a769c8266358a035bf5786e94d36940d54104428e607c1ee1453db0f52f10bb965b85d31e2f380dc6e90ec1cc1a279a242").unwrap();

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
