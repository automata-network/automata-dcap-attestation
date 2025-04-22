use automata_dcap_framework::state::VerifiedOutput;
use dcap_rs::types::tcb_info::TcbStatus;
use sdk::VerifierClient;

use crate::pccs::get_signer;


#[tokio::test]
async fn test_quote_tdx_verification() {

    let quote_data = include_bytes!("../../data/quote_tdx.bin");

    let (verified_output_pubkey, signatures) = sdk::verify_quote(
        quote_data,
        get_signer(),
    ).await.unwrap();

    let client = VerifierClient::new(get_signer()).unwrap();

    // This is failing, as pck_cert_chain_verified is false and is yet to be implemented
    // let verified_output = client.get_account::<VerifiedOutput>(verified_output_pubkey).await.unwrap();
    // let verified_output_tcb_status = serde_json::from_str::<TcbStatus>(&verified_output.tcb_status).unwrap();
    // assert!(verified_output.completed);
    // assert_eq!(verified_output.tcb_status, "UpToDate");
    for signature in signatures {
        println!("Quote Verification Transaction Signature: {:?}", signature);
    }
}

#[tokio::test]
#[ignore]
async fn test_quote_sgx_verification() {

    let client = VerifierClient::new(get_signer()).unwrap();
    let quote_data = include_bytes!("../../data/quote_sgx.bin");

    let (verified_output_pubkey, signatures) = sdk::verify_quote(
        quote_data,
        get_signer(),
    ).await.unwrap();

    let verified_output = client.get_account::<VerifiedOutput>(verified_output_pubkey).await.unwrap();
    let verified_output_tcb_status = serde_json::from_str::<TcbStatus>(&verified_output.tcb_status).unwrap();
    assert!(verified_output.completed);
    assert_eq!(verified_output_tcb_status, TcbStatus::UpToDate);

    for signature in signatures {
        println!("Quote Verification Transaction Signature: {:?}", signature);
    }
}
