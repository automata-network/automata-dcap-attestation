use std::sync::Arc;
use sdk::Sdk;
use sdk::models::{EnclaveIdentityType, CertificateAuthority};
use sdk::pccs::automata_on_chain_pccs::types::ZkvmSelector;
use sdk::pccs::{EcdsaZkVerifyInputType, request_ecdsa_verify_proof};
use anchor_client::solana_sdk::signer::keypair::Keypair;
use crate::{ROOT_CRL_BYTES, TEST_RISC0_VERIFIER_PUBKEY};
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
    //     issuer_der.as_slice(),
    //     Some(ROOT_CRL_BYTES)
    // )
    // .await
    // .unwrap();

    let proof = hex::decode("0b33e6fc719a4b059439f5cd581a765bc1fe74eafec0300e7146f50d4a2a518d2d84cdf26cf5d7bafe214a80b4f471dc3f7c6ca254370f789dfc60861b7f036324644cd3663d1fbd7b3078dedd1bb993ce0b6622f8833ba83b10b5d8ba2a91f025ac7277169804f79d8d0432056f6b5d64550fc8b0c50fa76fbb5555a126d9dd1fd7bf76a626dad36314e67789c16488031df4d406b31e000bc36235fb7c1b670568b4248d1f59b2b956dab49c4f3a73570b595b90c068cce92e6d173f296744148c0ed33bd91fe6ec6f0bf97ae3799c231d2f6eb100c4f9321356177f151cfc0ebefade64508ab456999faf4def63f0a91862babf224bf1786c19a7033a1974").unwrap();

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
