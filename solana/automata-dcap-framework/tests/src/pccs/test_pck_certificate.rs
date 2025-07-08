use crate::TEST_ZKVM_VERIFIER_PUBKEY;
use anchor_client::solana_sdk::signer::keypair::Keypair;
use sdk::Sdk;
use sdk::models::CertificateAuthority;
use sdk::pccs::EcdsaZkVerifyInputType;
use sdk::pccs::automata_on_chain_pccs::types::ZkvmSelector;
use sdk::shared::zk::RequestProof;
use sdk::shared::zk::sp1::SP1RequestArguments;
use std::sync::Arc;

pub(crate) async fn test_pck_certificate_upsert(sdk: &Sdk<Arc<Keypair>>) {
    let pck_cert_data = include_bytes!("../../data/pck.der").to_vec();

    let client = sdk.pccs_client();
    let data_buffer_pubkey = client
        .upload_pck_data(pck_cert_data.as_slice(), None)
        .await
        .unwrap();

    // let (_, issuer_der) = client
    //     .get_pcs_certificate(CertificateAuthority::PLATFORM, false)
    //     .await
    //     .unwrap();
    // let sp1_args = SP1RequestArguments {
    //     input_type: EcdsaZkVerifyInputType::X509,
    //     subject_data: pck_cert_data.clone(),
    //     issuer_raw_der: issuer_der,
    // };
    // let (_vkey, _output, proof) = sp1_args.request_p256_proof().await.unwrap();

    // println!("Proof: {}", hex::encode(&proof));
    let proof = hex::decode("a4594c590e3d3f92bd9b4405351de6196bc2a34d60a78d7811b95acf5350d49087d2af68100d7eca1f817531017a3882116c2e3d4b5a628329efa96fa6e627a94a905000091dbacc2ab32611d2642a92da7ec2d330591f550211670d01aaac822366758d15a21b006c78a4f469d83138f0eee1acc7b6f1781c97ebc4dbf4d1125b88c253124bf74c834c366023ac4d662ffe4486481b6b5e80db02d77bff1b38c774f0921b4c91616eb3092b9488ff26c9d2a1abd643ab6bf1dc4da457966a9b5faa7a071cf80aff611e1d47dffb994f53235dc255f11fc7a18cdff549f583b1b6dab61b04109976bcf3c0514a0690136bbef1c1f8d346c4fa1181b7e761e0ad965a6762").unwrap();

    let qe_id = "ad04024c9dfb382baf51ca3e5d6cb6e6";
    let pce_id = "0000";
    let tcbm = "0c0c0303ffff010000000000000000000d00";

    let _tx = client
        .upsert_pck_certificate(
            data_buffer_pubkey,
            TEST_ZKVM_VERIFIER_PUBKEY,
            qe_id.to_string(),
            pce_id.to_string(),
            tcbm.to_string(),
            ZkvmSelector::Succinct,
            proof,
        )
        .await
        .unwrap();

    let (_, pck_cert) = client
        .get_pck_certificate(qe_id.to_string(), pce_id.to_string(), tcbm.to_string())
        .await
        .unwrap();

    assert_eq!(pck_cert, pck_cert_data);
}
