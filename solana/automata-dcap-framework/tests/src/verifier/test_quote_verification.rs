use sdk::VerifierClient;
use sdk::automata_dcap_verifier::types::ZkvmSelector;
use solana_zk_tests::zkvm::risc0::deploy_risc0_groth16_verifier;
use anchor_client::solana_sdk::commitment_config::CommitmentConfig;
use anchor_client::solana_client::nonblocking::rpc_client::RpcClient;
use crate::pccs::get_signer;
use crate::{setup_solana_zk_program, TEST_RISC0_VERIFIER_PUBKEY};

#[tokio::test]

async fn test_quote_tdx_verification() {
    let quote_data = include_bytes!("../../data/quote_tdx.bin");
    let signer = get_signer();

    let verifier_client = VerifierClient::new(signer.clone()).unwrap();
    let anchor_client = verifier_client
        .anchor_client();

    let rpc_client = RpcClient::new_with_commitment(
        String::from("http://localhost:8899"),
        CommitmentConfig::confirmed(),
    );
    if rpc_client.get_account(&TEST_RISC0_VERIFIER_PUBKEY).await.is_err() {
        deploy_risc0_groth16_verifier(
            signer.as_ref(), 
            &rpc_client
        ).await.unwrap();
    }

    setup_solana_zk_program(
        anchor_client,
        signer.as_ref(),
        1,
        &TEST_RISC0_VERIFIER_PUBKEY
    ).await.unwrap();

    let (verified_output_pubkey, signatures) = sdk::verify_quote(
        ZkvmSelector::RiscZero,
        TEST_RISC0_VERIFIER_PUBKEY,
        quote_data,
        signer,
    )
    .await
    .unwrap();

    // let verified_output = verifier_client
    //     .get_account::<VerifiedOutput>(verified_output_pubkey)
    //     .await
    //     .unwrap();

    // assert_eq!(verified_output.tcb_status, "UpToDate");

    for signature in signatures {
        println!("Quote Verification Transaction Signature: {:?}", signature);
    }
}

#[tokio::test]
#[ignore]
async fn test_quote_sgx_verification() {
    let signer = get_signer();
    let quote_data = include_bytes!("../../data/quote_sgx.bin");

    let client = VerifierClient::new(signer.clone()).unwrap();
    let anchor_client = client.anchor_client();
    let quote_buffer_pubkey = client
        .init_quote_buffer(
            quote_data.len() as u32
        )
        .await
        .unwrap();

    let verified_output_pubkey = client.init_verified_output_account().await.unwrap();

    client
        .upload_chunks(quote_buffer_pubkey, quote_data, 512)
        .await
        .unwrap();

    let rpc_client = RpcClient::new_with_commitment(
        String::from("http://localhost:8899"),
        CommitmentConfig::confirmed(),
    );
    if rpc_client.get_account(&TEST_RISC0_VERIFIER_PUBKEY).await.is_err() {
        deploy_risc0_groth16_verifier(
            signer.as_ref(), 
            &rpc_client
        ).await.unwrap();
    }

    setup_solana_zk_program(
        anchor_client,
        signer.as_ref(),
        1,
        &TEST_RISC0_VERIFIER_PUBKEY
    ).await.unwrap();

    let signatures = client
        .verify_quote(
            quote_buffer_pubkey,
            ZkvmSelector::RiscZero,
            TEST_RISC0_VERIFIER_PUBKEY,
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
