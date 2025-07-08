use anchor_client::solana_sdk::signer::keypair::Keypair;
use dcap_rs::types::tcb_info::{TcbInfoAndSignature, TcbInfoVersion};
use sdk::Sdk;
use sdk::models::{CertificateAuthority, TcbType};
use sdk::pccs::EcdsaZkVerifyInputType;
use sdk::pccs::automata_on_chain_pccs::types::ZkvmSelector;
use sdk::shared::zk::RequestProof;
use sdk::shared::zk::sp1::SP1RequestArguments;

use std::str::FromStr;
use std::sync::Arc;

use crate::TEST_ZKVM_VERIFIER_PUBKEY;

// pub(crate) async fn test_tcb_info_upsert_v3_sgx(sdk: &Sdk<Arc<Keypair>>) {
//     let tcb_info_data = include_bytes!("../../data/tcb_info_v3_sgx.json");

//     let tcb_info_and_signature: TcbInfoAndSignature =
//         serde_json::from_slice(tcb_info_data).unwrap();
//     let tcb_info_parsed = tcb_info_and_signature.get_tcb_info().unwrap();

//     let client = sdk.pccs_client();
//     let data_buffer_pubkey = client
//         .upload_tcb_data(tcb_info_data.as_slice(), None)
//         .await
//         .unwrap();

//     let data_buffer_account_data = client.load_buffer_data(data_buffer_pubkey).await.unwrap();

//     let (_, issuer_der) = client
//         .get_pcs_certificate(CertificateAuthority::SIGNING, false)
//         .await
//         .unwrap();

//     let (_image_id, _journal, proof) = request_ecdsa_verify_proof(
//         EcdsaZkVerifyInputType::TcbInfo,
//         data_buffer_account_data.as_slice(),
//         issuer_der.as_slice(),
//     )
//     .await
//     .unwrap();

//     let tcb_type = TcbType::Sgx;
//     let fmspc = "00A067110000";
//     let fmspc_bytes: [u8; 6] = hex::decode(fmspc).unwrap().try_into().unwrap();
//     let _tx = client
//         .upsert_tcb_info(
//             data_buffer_pubkey,
//             TEST_ZKVM_VERIFIER_PUBKEY,
//             tcb_type,
//             3,
//             fmspc_bytes,
//             ZkvmSelector::Succinct,
//             proof,
//         )
//         .await
//         .unwrap();

//     let (_, tcb_info) = client.get_tcb_info(tcb_type, fmspc_bytes, 3).await.unwrap();
//     assert_eq!(&tcb_info_parsed, &tcb_info);

//     let tcb_type_string = tcb_info.id.unwrap_or_else(|| "SGX".to_string());
//     let actual_tcb_type: TcbType = TcbType::from_str(&tcb_type_string).unwrap();

//     assert_eq!(tcb_info.version, TcbInfoVersion::V3);
//     assert_eq!(actual_tcb_type, tcb_type);
//     assert_eq!(tcb_info.fmspc, fmspc);
// }

pub(crate) async fn test_tcb_info_upsert_v3_tdx(sdk: &Sdk<Arc<Keypair>>) {
    let tcb_info_data = include_bytes!("../../data/tcb_info_v3_with_tdx_module.json");

    let tcb_info_and_signature: TcbInfoAndSignature =
        serde_json::from_slice(tcb_info_data).unwrap();
    let tcb_info_parsed = tcb_info_and_signature.get_tcb_info().unwrap();

    let client = sdk.pccs_client();
    let data_buffer_pubkey = client
        .upload_tcb_data(tcb_info_data.as_slice(), None)
        .await
        .unwrap();

    let data_buffer_account_data = client.load_buffer_data(data_buffer_pubkey).await.unwrap();

    // let (_, issuer_der) = client
    //     .get_pcs_certificate(CertificateAuthority::SIGNING, false)
    //     .await
    //     .unwrap();

    // let sp1_args = SP1RequestArguments {
    //     input_type: EcdsaZkVerifyInputType::TcbInfo,
    //     subject_data: data_buffer_account_data,
    //     issuer_raw_der: issuer_der,
    // };
    // let (_vkey, _output, proof) = sp1_args.request_p256_proof().await.unwrap();

    // print!("Proof: {}", hex::encode(&proof));
    let proof = hex::decode("a4594c5923f2ac2edf204c94d0856e5a0b3570180c18dd465988185ff5bf466dcd507256206e3e9fd7df8ab0a9d672e40ab9dba30411ba5a5ee7a6bf8d22bb306bd7fdaa12a5bc14ae0a72d15f02ce7e7207e303fa77480adb16224c4bbf843898a8f27d15fa1d6e4d56bb2751d88d0808805e1e33f68e8519b16818de28cf674374b45922e48eae3dc87dc0420be72c8f95f3d699f12eee30c92c3bbfc79764e01dae9f07bf8cb5091219dec05f738307b05bc1fb0586f9c20a56e5575508364a80a2ac1a15395d57a1b1bc153fca96ec8b73957ab9a5da10e78af240ad5dbc6b46777204ee0bde262218fc92157e9b80e14946735cb1296951ba4f811f7c9222ad3955").unwrap();

    let tcb_type = TcbType::Tdx;
    let fmspc = "00806f050000";
    let fmspc_bytes: [u8; 6] = hex::decode(fmspc).unwrap().try_into().unwrap();
    let _tx = client
        .upsert_tcb_info(
            data_buffer_pubkey,
            TEST_ZKVM_VERIFIER_PUBKEY,
            tcb_type,
            3,
            fmspc_bytes,
            ZkvmSelector::Succinct,
            proof,
        )
        .await
        .unwrap();

    let (_, tcb_info) = client.get_tcb_info(tcb_type, fmspc_bytes, 3).await.unwrap();
    assert_eq!(&tcb_info_parsed, &tcb_info);

    let tcb_type_string = tcb_info.id.unwrap_or_else(|| "SGX".to_string());
    let actual_tcb_type: TcbType = TcbType::from_str(&tcb_type_string).unwrap();

    assert_eq!(tcb_info.version, TcbInfoVersion::V3);
    assert_eq!(actual_tcb_type, tcb_type);
    assert_eq!(tcb_info.fmspc, fmspc);
}
