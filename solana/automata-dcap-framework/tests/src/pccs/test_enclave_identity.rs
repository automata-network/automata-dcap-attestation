use crate::TEST_ZKVM_VERIFIER_PUBKEY;
use anchor_client::solana_sdk::signer::keypair::Keypair;
use dcap_rs::types::enclave_identity::{EnclaveType, QuotingEnclaveIdentityAndSignature};
use sdk::Sdk;
use sdk::models::{CertificateAuthority, EnclaveIdentityType};
use sdk::pccs::EcdsaZkVerifyInputType;
use sdk::pccs::automata_on_chain_pccs::types::ZkvmSelector;
use sdk::shared::zk::RequestProof;
use sdk::shared::zk::sp1::SP1RequestArguments;
use std::sync::Arc;

pub(crate) async fn test_enclave_identity_upsert(sdk: &Sdk<Arc<Keypair>>) {
    let enclave_identity_data = include_bytes!("../../data/qe_identity.json").to_vec();

    let client = sdk.pccs_client();
    let data_buffer_pubkey = client
        .upload_identity_data(enclave_identity_data.as_slice(), None)
        .await
        .unwrap();

    let (_, issuer_der) = client
        .get_pcs_certificate(CertificateAuthority::SIGNING, false)
        .await
        .unwrap();

    let enclave_identity_on_chain_data = client.load_buffer_data(data_buffer_pubkey).await.unwrap();
    let sp1_args = SP1RequestArguments {
        input_type: EcdsaZkVerifyInputType::Identity,
        subject_data: enclave_identity_on_chain_data,
        issuer_raw_der: issuer_der,
    };
    let (_vkey, _output, proof) = sp1_args.request_p256_proof().await.unwrap();

    println!("Proof: {}", hex::encode(&proof));
    // let proof = hex::decode("").unwrap();

    let _tx = client
        .upsert_enclave_identity(
            data_buffer_pubkey,
            TEST_ZKVM_VERIFIER_PUBKEY,
            EnclaveIdentityType::TdQe,
            2,
            ZkvmSelector::Succinct,
            proof,
        )
        .await
        .unwrap();

    let (_, enclave_identity) = client
        .get_enclave_identity(EnclaveIdentityType::TdQe, 2)
        .await
        .unwrap();

    let enclave_identity_and_signature: QuotingEnclaveIdentityAndSignature =
        serde_json::from_slice(&enclave_identity_data).unwrap();
    let enclave_identity_parsed = enclave_identity_and_signature
        .get_enclave_identity()
        .unwrap();

    assert_eq!(&enclave_identity_parsed, &enclave_identity);

    let actual_identity_type = enclave_identity.id;
    let expected_identity_type = EnclaveType::TdQe;
    assert_eq!(actual_identity_type, expected_identity_type);
    assert_eq!(enclave_identity.version, 2);
}
