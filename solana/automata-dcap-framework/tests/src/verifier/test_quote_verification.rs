use std::sync::Arc;
use sdk::Sdk;
use anchor_client::solana_sdk::signer::keypair::Keypair;
use sdk::verifier::automata_dcap_verifier::types::ZkvmSelector;
use crate::TEST_RISC0_VERIFIER_PUBKEY;

pub(crate) async fn test_quote_tdx_verification(sdk: &Sdk<Arc<Keypair>>) {
    let quote_data = include_bytes!("../../data/quote_tdx.bin");
    let _verifier_client = sdk.verifier_client();
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

pub(crate) async fn test_quote_sgx_verification(sdk: &Sdk<Arc<Keypair>>) {
    let quote_data = include_bytes!("../../data/quote_sgx.bin");

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
