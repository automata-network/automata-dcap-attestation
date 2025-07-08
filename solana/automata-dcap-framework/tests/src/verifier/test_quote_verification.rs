use crate::TEST_ZKVM_VERIFIER_PUBKEY;
use anchor_client::solana_sdk::signer::keypair::Keypair;
use dcap_rs::types::tcb_info::TcbStatus;
use sdk::pccs::EcdsaZkVerifyInputType;
use sdk::shared::zk::RequestProof;
use sdk::verifier::automata_dcap_verifier::types::ZkvmSelector;
use sdk::{Sdk, shared::zk::sp1::SP1RequestArguments};
use std::sync::Arc;
use x509_parser::pem::Pem;

pub(crate) async fn test_quote_tdx_verification(sdk: &Sdk<Arc<Keypair>>) {
    let quote_data = include_bytes!("../../data/quote_tdx.bin");
    let verifier_client = sdk.verifier_client();

    let cert_chain = get_cert_chain_from_quote_data(quote_data);
    let mut der_chain: Vec<Vec<u8>> = vec![];
    for pem in Pem::iter_from_buffer(cert_chain.as_slice()) {
        der_chain.push(pem.unwrap().contents);
    }
    assert!(
        der_chain.len() == 3,
        "PCK Certificate Chain must contain exactly 3 certificates"
    );

    let proofs: [Vec<u8>; 3] = [
        vec![
            164, 89, 76, 89, 3, 204, 154, 84, 6, 40, 8, 195, 135, 198, 78, 70, 204, 245, 196, 85,
            200, 197, 93, 252, 106, 250, 246, 104, 30, 14, 74, 113, 197, 23, 205, 143, 20, 173,
            172, 187, 158, 7, 78, 29, 195, 183, 143, 232, 130, 83, 70, 148, 77, 164, 164, 46, 96,
            162, 225, 130, 201, 202, 205, 206, 92, 113, 196, 205, 19, 199, 29, 210, 88, 175, 228,
            231, 150, 207, 173, 192, 117, 107, 136, 146, 229, 130, 98, 228, 163, 182, 35, 12, 42,
            43, 233, 66, 210, 141, 15, 116, 19, 14, 206, 32, 60, 242, 10, 100, 72, 83, 201, 138,
            64, 225, 183, 233, 37, 117, 52, 223, 112, 64, 30, 19, 78, 172, 26, 89, 164, 14, 46,
            126, 17, 129, 70, 83, 169, 143, 116, 197, 60, 108, 166, 165, 49, 128, 192, 183, 100,
            185, 66, 67, 37, 183, 233, 163, 154, 195, 215, 34, 180, 103, 68, 152, 30, 207, 156, 51,
            249, 52, 161, 189, 237, 93, 198, 182, 231, 248, 194, 241, 245, 41, 166, 44, 152, 151,
            199, 107, 98, 40, 206, 76, 196, 154, 237, 254, 19, 159, 17, 46, 121, 68, 66, 99, 230,
            192, 220, 14, 154, 21, 6, 128, 226, 36, 24, 111, 118, 220, 35, 45, 203, 116, 127, 39,
            101, 116, 32, 236, 31, 213, 11, 133, 169, 29, 110, 243, 15, 61, 198, 58, 210, 50, 41,
            82, 94, 5, 151, 235, 66, 119, 64, 245, 84, 168, 54, 128, 62, 27, 213, 151,
        ],
        vec![
            164, 89, 76, 89, 47, 175, 12, 190, 47, 98, 220, 217, 158, 11, 42, 137, 105, 152, 125,
            234, 9, 34, 60, 252, 155, 127, 123, 221, 130, 164, 101, 66, 240, 81, 182, 0, 16, 37,
            245, 51, 186, 23, 220, 174, 206, 229, 203, 207, 127, 103, 118, 154, 0, 38, 7, 72, 194,
            172, 208, 246, 78, 137, 23, 148, 12, 240, 1, 41, 16, 6, 52, 60, 119, 31, 66, 13, 53,
            119, 74, 97, 153, 62, 35, 43, 229, 67, 215, 155, 148, 245, 229, 144, 236, 104, 74, 56,
            101, 131, 139, 119, 22, 15, 234, 62, 39, 63, 92, 245, 187, 31, 68, 47, 159, 228, 123,
            250, 35, 54, 128, 48, 248, 23, 197, 100, 170, 53, 68, 213, 6, 232, 20, 201, 3, 170,
            128, 41, 255, 163, 141, 139, 2, 172, 57, 77, 102, 52, 214, 69, 230, 34, 190, 29, 28,
            157, 138, 201, 140, 45, 140, 37, 240, 99, 253, 61, 31, 56, 119, 165, 232, 52, 87, 157,
            235, 24, 120, 153, 153, 139, 61, 51, 24, 146, 189, 180, 76, 202, 183, 120, 138, 101,
            83, 93, 126, 44, 212, 200, 35, 200, 250, 72, 209, 54, 10, 251, 99, 190, 225, 130, 121,
            185, 136, 200, 187, 10, 241, 97, 252, 118, 55, 144, 188, 83, 66, 132, 110, 167, 45,
            165, 47, 147, 53, 48, 37, 245, 185, 107, 249, 87, 37, 19, 153, 158, 14, 253, 87, 162,
            154, 181, 127, 240, 165, 28, 179, 89, 162, 165, 133, 31, 161, 78,
        ],
        vec![
            164, 89, 76, 89, 45, 152, 88, 127, 245, 36, 75, 202, 134, 152, 1, 104, 227, 32, 210,
            163, 67, 84, 221, 55, 195, 140, 240, 132, 216, 82, 80, 245, 245, 68, 188, 114, 21, 61,
            114, 255, 125, 116, 218, 20, 226, 45, 233, 251, 225, 146, 112, 170, 114, 5, 88, 132,
            40, 195, 17, 138, 6, 126, 151, 49, 229, 101, 26, 185, 12, 173, 102, 56, 13, 134, 247,
            163, 63, 114, 195, 60, 169, 20, 253, 144, 200, 129, 140, 210, 9, 162, 188, 2, 207, 78,
            230, 63, 80, 47, 34, 180, 2, 4, 228, 194, 191, 36, 215, 51, 139, 238, 247, 212, 30,
            210, 59, 151, 140, 211, 88, 215, 240, 31, 167, 164, 57, 215, 34, 221, 91, 147, 93, 233,
            22, 141, 37, 49, 204, 239, 109, 184, 42, 252, 130, 1, 252, 105, 66, 23, 30, 141, 245,
            95, 112, 40, 203, 10, 157, 243, 84, 105, 19, 105, 26, 27, 31, 2, 252, 196, 188, 225,
            209, 225, 100, 115, 245, 87, 127, 164, 142, 176, 137, 212, 110, 77, 39, 133, 107, 198,
            253, 36, 83, 236, 239, 31, 130, 11, 23, 122, 115, 99, 60, 223, 67, 115, 175, 205, 38,
            180, 37, 233, 117, 126, 111, 186, 252, 217, 218, 86, 178, 175, 166, 135, 37, 57, 59,
            219, 255, 125, 18, 211, 19, 4, 108, 221, 92, 25, 123, 29, 12, 75, 7, 52, 39, 255, 236,
            77, 222, 238, 162, 50, 74, 146, 219, 119, 0, 219, 122, 18, 140, 66,
        ],
    ];

    // let mut proofs: [Vec<u8>; 3] = [vec![], vec![], vec![]];

    // for (i, cert) in der_chain.iter().enumerate() {
    //     let issuer_cert = if i == 2 {
    //         cert
    //     } else {
    //         der_chain[i + 1].as_slice()
    //     };

    //     let sp1_args = SP1RequestArguments {
    //         input_type: EcdsaZkVerifyInputType::X509,
    //         subject_data: cert.to_vec(),
    //         issuer_raw_der: issuer_cert.to_vec()
    //     };
    //     let (_vkey, _output, proof) = sp1_args.request_p256_proof().await.unwrap();

    //     println!("proof {}: {:?}", i, proof);

    //     proofs[i] = proof;
    // }

    let (verified_output_pubkey, signatures) = sdk
        .verify_quote(
            TEST_ZKVM_VERIFIER_PUBKEY,
            ZkvmSelector::Succinct,
            quote_data,
            proofs,
        )
        .await
        .unwrap();

    let verified_output = verifier_client
        .get_verified_output(verified_output_pubkey)
        .await
        .unwrap();

    println!("Verified output: {:?}", verified_output);

    assert_eq!(verified_output.quote_version, 4);
    assert_eq!(verified_output.quote_body_type, 2);
    assert_eq!(verified_output.tcb_status, TcbStatus::OutOfDate as u8);

    for signature in signatures {
        println!("Quote Verification Transaction Signature: {:?}", signature);
    }
}

// pub(crate) async fn test_quote_sgx_verification(sdk: &Sdk<Arc<Keypair>>) {
//     let quote_data = include_bytes!("../../data/quote_sgx.bin");

//     let verifier_client = sdk.verifier_client();
//     let (quote_buffer_pubkey, verified_output_pubkey) = verifier_client
//         .init_quote_buffer(
//             quote_data.len() as u32
//         )
//         .await
//         .unwrap();

//     verifier_client
//         .upload_chunks(quote_buffer_pubkey, quote_data, 512)
//         .await
//         .unwrap();

//     let pem_chain = get_cert_chain_from_quote_data(quote_data);
//     // let (_,_,proof) = verify_pck_chain_zk(pem_chain.as_slice()).await.unwrap();

//     let signatures = verifier_client
//         .verify_quote(
//             quote_buffer_pubkey,
//             verified_output_pubkey,
//             TEST_ZKVM_VERIFIER_PUBKEY,
//             ZkvmSelector::Succinct,
//             proof
//         )
//         .await
//         .unwrap();

//     for signature in signatures {
//         println!("Quote Verification Transaction Signature: {:?}", signature);
//     }
// }

use dcap_rs::types::quote::Quote;
fn get_cert_chain_from_quote_data(quote_data: &[u8]) -> Vec<u8> {
    let mut quote_data_ref = quote_data;
    let quote = Quote::read(&mut quote_data_ref).unwrap();
    let pem_chain = quote.signature.cert_data.cert_data;
    pem_chain.to_vec()
}
