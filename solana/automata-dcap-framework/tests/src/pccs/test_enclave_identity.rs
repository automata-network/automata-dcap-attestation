use std::sync::Arc;
use sdk::Sdk;
use anchor_client::solana_sdk::signer::keypair::Keypair;
use crate::TEST_RISC0_VERIFIER_PUBKEY;
use sdk::EnclaveIdentityType;
use sdk::automata_on_chain_pccs::types::ZkvmSelector;

pub(crate) async fn test_enclave_identity_upsert(sdk: &Sdk<Arc<Keypair>>) {
    let enclave_identity_data = include_bytes!("../../data/qe_identity.json").to_vec();

    let client = sdk.pccs_client();
    let data_buffer_pubkey = client.init_data_buffer(enclave_identity_data.len() as u32).await.unwrap();
    client.upload_chunks(data_buffer_pubkey, &enclave_identity_data, 512).await.unwrap();

    let _tx = client.upsert_enclave_identity(
        EnclaveIdentityType::TdQe,
        2,
        data_buffer_pubkey,
        ZkvmSelector::RiscZero,
        TEST_RISC0_VERIFIER_PUBKEY
    ).await.unwrap();

    let enclave_identity = client.get_enclave_identity(
        EnclaveIdentityType::TdQe,
        2,
    ).await.unwrap();

    let actual_identity_type: EnclaveIdentityType = enclave_identity.identity_type.into();
    let expected_identity_type = EnclaveIdentityType::TdQe;
    assert_eq!(actual_identity_type, expected_identity_type);
    assert_eq!(enclave_identity.version, 2);
    assert_eq!(enclave_identity.data, enclave_identity_data);
}
