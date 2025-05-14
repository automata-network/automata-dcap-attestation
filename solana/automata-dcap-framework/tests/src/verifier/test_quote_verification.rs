use std::sync::Arc;
use sdk::Sdk;
use sdk::shared::pck::verify_pck_chain_zk;
use anchor_client::solana_sdk::signer::keypair::Keypair;
use sdk::verifier::automata_dcap_verifier::types::ZkvmSelector;
use crate::TEST_RISC0_VERIFIER_PUBKEY;

pub(crate) async fn test_quote_tdx_verification(sdk: &Sdk<Arc<Keypair>>) {
    let quote_data = include_bytes!("../../data/quote_tdx.bin");
    let _verifier_client = sdk.verifier_client();

    // let pem_chain = get_cert_chain_from_quote_data(quote_data);
    // let (_,_,proof) = verify_pck_chain_zk(pem_chain.as_slice()).await.unwrap();
    let proof = hex::decode("175b77af0b321ec2a4ad5bf91bf2b21e29b4575e6cf33d9ac24f4e8e1566155628388df6e4eb995e032f95a73ba4224c15ba9afd597c9e11e1cb4c2083cf46bc1f711d130af1207da437db77587d253c08f3b9b5e00c09d3526b5db16f7e8c3017aa789137e4388cdad634d42b1876eadbc0c6b85b28fdc5edde33f3a5ad40812cc18431799878adb9b85e9573214e3ccf37a92f335ff06ccbc54e18b05674e3117d1bb98e7383bde38925d185806159de676b3a80df1136d00714ee43969613267a4df3ae793806a196a7dbc3256c3724858ffc958e4de5d47c0354757a8fa71679bb580231c1af33e9f03e94544550973e581f35dd5084d43899cff2fb90e5").unwrap();
    let (verified_output_pubkey, signatures) = sdk.verify_quote(
        TEST_RISC0_VERIFIER_PUBKEY,
        ZkvmSelector::RiscZero,
        quote_data,
        proof
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

    let pem_chain = get_cert_chain_from_quote_data(quote_data);
    let (_,_,proof) = verify_pck_chain_zk(pem_chain.as_slice()).await.unwrap();

    let signatures = verifier_client
        .verify_quote(
            quote_buffer_pubkey,
            TEST_RISC0_VERIFIER_PUBKEY,
            ZkvmSelector::RiscZero,
            proof
        )
        .await
        .unwrap();

    for signature in signatures {
        println!("Quote Verification Transaction Signature: {:?}", signature);
    }
}

use dcap_rs::types::quote::Quote;
fn get_cert_chain_from_quote_data(quote_data: &[u8]) -> Vec<u8> {
    let mut quote_data_ref = quote_data;
    let quote = Quote::read(&mut quote_data_ref).unwrap();
    let pem_chain = quote.signature.cert_data.cert_data;
    pem_chain.to_vec()
}