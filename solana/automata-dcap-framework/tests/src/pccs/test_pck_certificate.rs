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

    let (_, issuer_der) = client
        .get_pcs_certificate(CertificateAuthority::PLATFORM, false)
        .await
        .unwrap();
    let sp1_args = SP1RequestArguments {
        input_type: EcdsaZkVerifyInputType::X509,
        subject_data: pck_cert_data.clone(),
        issuer_raw_der: issuer_der,
    };
    let (_vkey, _output, proof) = sp1_args.request_p256_proof().await.unwrap();

    println!("Proof: {}", hex::encode(&proof));
    // let proof = hex::decode("03e7cdba01a2cdd524f1c89a6a87fdd7f02185027117db036401400e1cb77f790c405deffdeb0a041604b5994c2c15706b73cf4b26a8c619ffa40f55bc1ace2a1895e02381b5ed1337284eaf779cc1ca4d1f600c56d9b55afc4d1dc34672fa700e70b96dd8c916efeedeeb47656fb245e712f74858efc5b5efe4980e7eb154d7219d49f215ede5d8c81ee7bfd578fe0847ab7e5ebdb66e3ef7f12f06e23bade20219569d89fc3726a5d2d2b77865a27d951840e29928ddd92c01001063a85f6b0636588dff8a292fc3f28f8210a5cf128fa94210d39671a733a8d3b885637f79253429067187c54edcb1b3edde942c80338a67d8e290908e4df16eca08475667").unwrap();

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
