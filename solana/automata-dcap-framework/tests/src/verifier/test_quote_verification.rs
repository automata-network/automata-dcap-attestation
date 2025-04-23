use sdk::automata_dcap_verifier::types::ZkvmSelector;
use solana_zk_tests::zkvm::risc0::deploy_risc0_groth16_verifier;
use anchor_client::solana_sdk::commitment_config::CommitmentConfig;
use anchor_client::solana_client::nonblocking::rpc_client::RpcClient;
use crate::pccs::get_signer;
use crate::TEST_RISC0_VERIFIER_PUBKEY;

#[tokio::test]

async fn test_quote_tdx_verification() {
    let quote_data = include_bytes!("../../data/quote_tdx.bin");
    let signer = get_signer();

    let sdk = sdk::Sdk::new(signer.clone(), None);
    let _verifier_client = sdk.verifier_client();

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

    let (verified_output_pubkey, signatures) = sdk.verify_quote(
        ZkvmSelector::RiscZero,
        TEST_RISC0_VERIFIER_PUBKEY,
        quote_data
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

    let sdk = sdk::Sdk::new(signer.clone(), None);
    let verifier_client = sdk.verifier_client();
    let quote_buffer_pubkey = verifier_client
        .init_quote_buffer(
            quote_data.len() as u32
        )
        .await
        .unwrap();

    verifier_client
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

    let signatures = verifier_client
        .verify_quote(
            quote_buffer_pubkey,
            ZkvmSelector::RiscZero,
            TEST_RISC0_VERIFIER_PUBKEY,
        )
        .await
        .unwrap();

    for signature in signatures {
        println!("Quote Verification Transaction Signature: {:?}", signature);
    }
}

// TODO: make client for Solana ZK
