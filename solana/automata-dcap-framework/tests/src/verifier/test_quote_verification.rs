use anchor_client::solana_client::nonblocking::rpc_client::RpcClient;
use anchor_client::solana_sdk::commitment_config::CommitmentConfig;
use anchor_client::solana_sdk::signer::Signer;
// use anchor_client::Program;
// use anchor_client::Config;
use automata_dcap_framework::state::VerifiedOutput;
use dcap_rs::types::tcb_info::TcbStatus;
use sdk::VerifierClient;
use sdk::automata_dcap_verifier::types::ZkvmSelector;
// use solana_zk_client::SolanaZkClient;
use solana_zk_tests::zkvm::risc0::deploy_risc0_groth16_verifier;

use crate::pccs::get_signer;
use crate::setup_solana_zk_program;

#[tokio::test]

async fn test_quote_tdx_verification() {
    let quote_data = include_bytes!("../../data/quote_tdx.bin");
    let signer = get_signer();
    let rpc_client = RpcClient::new_with_commitment(
        "http://localhost:8899".to_string(),
        CommitmentConfig::confirmed(),
    );

    let zkvm_verifier_program_id = deploy_risc0_groth16_verifier(signer.as_ref(), &rpc_client)
        .await
        .unwrap();

    println!("zkvm verifier program id: {:?}", zkvm_verifier_program_id);

    let verifier_client = VerifierClient::new(get_signer()).unwrap();
    let anchor_client = verifier_client
        .anchor_client();
    let solana_zk_program = anchor_client.program(solana_zk::ID).unwrap();
    println!("solana zk program id: {:?}", solana_zk_program.id());

    setup_solana_zk_program(&solana_zk_program, &signer.pubkey(), 1, &zkvm_verifier_program_id).await.unwrap();

    let (verified_output_pubkey, signatures) = sdk::verify_quote(
        ZkvmSelector::RiscZero,
        zkvm_verifier_program_id,
        quote_data,
        signer,
    )
    .await
    .unwrap();

    let verified_output = verifier_client
        .get_account::<VerifiedOutput>(verified_output_pubkey)
        .await
        .unwrap();

    assert!(verified_output.completed);
    assert_eq!(verified_output.tcb_status, "UpToDate");

    for signature in signatures {
        println!("Quote Verification Transaction Signature: {:?}", signature);
    }
}

#[tokio::test]
#[ignore]
async fn test_quote_sgx_verification() {
    let client = VerifierClient::new(get_signer()).unwrap();
    let quote_data = include_bytes!("../../data/quote_sgx.bin");

    let quote_buffer_pubkey = client
        .init_quote_buffer(
            quote_data.len() as u32,
            sdk::get_num_chunks(quote_data.len(), 512),
        )
        .await
        .unwrap();

    let verified_output_pubkey = client.init_verified_output_account().await.unwrap();

    client
        .upload_chunks(quote_buffer_pubkey, quote_data, 512)
        .await
        .unwrap();

    let signer = get_signer();
    let rpc_client = RpcClient::new_with_commitment(
        "http://localhost:8899".to_string(),
        CommitmentConfig::confirmed(),
    );

    let zkvm_verifier_program_id = deploy_risc0_groth16_verifier(signer.as_ref(), &rpc_client)
        .await
        .unwrap();

    let signatures = client
        .verify_quote(
            ZkvmSelector::RiscZero,
            zkvm_verifier_program_id,
            quote_buffer_pubkey,
            verified_output_pubkey,
        )
        .await
        .unwrap();

    let verified_output = client.get_account::<VerifiedOutput>(verified_output_pubkey).await.unwrap();
    let verified_output_tcb_status = serde_json::from_str::<TcbStatus>(&verified_output.tcb_status).unwrap();
    assert!(verified_output.completed);
    assert_eq!(verified_output_tcb_status, TcbStatus::UpToDate);

    for signature in signatures {
        println!("Quote Verification Transaction Signature: {:?}", signature);
    }
}

// TODO: make client for Solana ZK
