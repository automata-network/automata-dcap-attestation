use automata_dcap_framework::state::VerifiedOutput;
use sdk::VerifierClient;

use crate::pccs::get_signer;


#[tokio::test]
async fn test_quote_tdx_verification() {

    let client = VerifierClient::new(get_signer()).unwrap();
    let quote_data = include_bytes!("../../data/quote_tdx.bin");

    let quote_buffer_pubkey = client
        .init_quote_buffer(
            quote_data.len() as u32,
            sdk::get_num_chunks(quote_data.len(), 512),
        )
        .await.unwrap();

    let verified_output_pubkey = client.init_verified_output_account().await.unwrap();

    client
        .upload_chunks(quote_buffer_pubkey, quote_data, 512)
        .await.unwrap();

    let signatures = client.verify_quote(
        quote_buffer_pubkey,
        verified_output_pubkey,
    ).await.unwrap();


    let verified_output = client.get_account::<VerifiedOutput>(verified_output_pubkey).await.unwrap();

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
        .await.unwrap();

    let verified_output_pubkey = client.init_verified_output_account().await.unwrap();

    client
        .upload_chunks(quote_buffer_pubkey, quote_data, 512)
        .await.unwrap();

    let signatures = client.verify_quote(
        quote_buffer_pubkey,
        verified_output_pubkey,
    ).await.unwrap();

    for signature in signatures {
        println!("Quote Verification Transaction Signature: {:?}", signature);
    }
}
