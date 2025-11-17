use crate::{ROOT_CRL_BYTES, TEST_ZKVM_VERIFIER_PUBKEY};
use anchor_client::solana_sdk::signer::keypair::Keypair;
use sdk::Sdk;
use sdk::models::CertificateAuthority;
use sdk::pccs::EcdsaZkVerifyInputType;
use sdk::pccs::automata_on_chain_pccs::types::ZkvmSelector;
use sdk::shared::zk::RequestProof;
use sdk::shared::zk::sp1::SP1RequestArguments;
use std::sync::Arc;

pub(crate) async fn test_pcs_root_ca_upsert(sdk: &Sdk<Arc<Keypair>>) {
    let client = sdk.pccs_client();
    let root_cert_data = include_bytes!("../../data/root.der").to_vec();
    let data_buffer_pubkey = client
        .upload_pcs_data(false, root_cert_data.as_slice(), None)
        .await
        .unwrap();

    // let sp1_args = SP1RequestArguments {
    //     input_type: EcdsaZkVerifyInputType::X509,
    //     subject_data: root_cert_data.clone(),
    //     issuer_raw_der: root_cert_data.clone(),
    // };
    // let (_vkey, _output, proof) = sp1_args.request_p256_proof().await.unwrap();

    // println!("Proof: {}", hex::encode(&proof));
    let proof = hex::decode("a4594c590b2cc2560ce2750c3882f894f4f0a421f6b802faceb0278c27dac82257930f200ed01f901a191e05df3c3c98b2a4157e46e135d93bf7f3e656a1924d4c4697332ad7f29602008e0b6afde8f2e7e9ae81ceed68d8801f97db023020237c471d7b1259add1374d33266594639b9768552578bb19fc6df4934316db7659be3c66d00466613d0c58e028fee061666a77eff494fc901e30012643618756347ca964bf16a0d5b5eb20dade18ef3e0b1024ab3381aa1f6dea709acb55c5426852e52b222c17481e37498f4f25184e5838a363eb91561237d1080cd4997042218d525d6712ad3fd45b2fbcd3925e4b8ed1e22726ed1ab67aaa83f551fbef504a31c2842b").unwrap();

    let ca_type = CertificateAuthority::ROOT;
    let _tx = client
        .upsert_pcs_certificate(
            data_buffer_pubkey,
            TEST_ZKVM_VERIFIER_PUBKEY,
            ca_type,
            ZkvmSelector::Succinct,
            proof,
        )
        .await
        .unwrap();

    let (_, pcs_cert) = client.get_pcs_certificate(ca_type, false).await.unwrap();
    assert_eq!(pcs_cert, root_cert_data);
}

pub(crate) async fn test_pcs_root_crl_certificate_upsert(sdk: &Sdk<Arc<Keypair>>) {
    let client = sdk.pccs_client();
    let pcs_crl_data = ROOT_CRL_BYTES.to_vec();
    let data_buffer_pubkey = client
        .upload_pcs_data(true, pcs_crl_data.as_slice(), None)
        .await
        .unwrap();

    let ca_type = CertificateAuthority::ROOT;

    // let (_, issuer_der) = client.get_pcs_certificate(ca_type, false).await.unwrap();

    // let sp1_args = SP1RequestArguments {
    //     input_type: EcdsaZkVerifyInputType::CRL,
    //     subject_data: pcs_crl_data.clone(),
    //     issuer_raw_der: issuer_der,
    // };
    // let (_vkey, _output, proof) = sp1_args.request_p256_proof().await.unwrap();

    // println!("Proof: {}", hex::encode(&proof));

    let proof = hex::decode("a4594c591311fefcfedbc6ca305a874c8375c988b3e04cc573dcfca4b09faa9e287fd91221e601cc74b95baad8cf7983631b36783339309fccb09bc05bd6fbd29514c8de2e90c522a623ad1edafec58bce9ea8ab0b5247fe6cba53815a27d40c07bc71f51c90e66e4722bf77720038a8d8a09bd5fd8a4705a191c2695f0dcb428a49c1c5273a04cb41086856d960176f5ef3bc284005280ae9fa73bda8ac34787c0741a915969ec35b1a74962d5e5929373a3a1d6bc8363b846e337a1548a61b2aa99b661570d00776ed0573951da6562a0435924d68ea12e53f6c82b8ecc84dc862d76c29b034b725121fba7ac0238b00404c65d24eddb80267d39c11fcb67563c182cc").unwrap();

    let _tx = client
        .upsert_pcs_crl(
            data_buffer_pubkey,
            TEST_ZKVM_VERIFIER_PUBKEY,
            ca_type,
            ZkvmSelector::Succinct,
            proof,
        )
        .await
        .unwrap();

    let (_, pcs_crl) = client.get_pcs_certificate(ca_type, true).await.unwrap();
    assert_eq!(pcs_crl, pcs_crl_data);
}

pub(crate) async fn test_pcs_signing_certificate_upsert(sdk: &Sdk<Arc<Keypair>>) {
    let client = sdk.pccs_client();
    let pcs_cert_data = include_bytes!("../../data/signing.der").to_vec();
    let data_buffer_pubkey = client
        .upload_pcs_data(false, pcs_cert_data.as_slice(), None)
        .await
        .unwrap();

    // let (_, issuer_der) = client
    //     .get_pcs_certificate(CertificateAuthority::ROOT, false)
    //     .await
    //     .unwrap();

    // let sp1_args = SP1RequestArguments {
    //     input_type: EcdsaZkVerifyInputType::X509,
    //     subject_data: pcs_cert_data.clone(),
    //     issuer_raw_der: issuer_der,
    // };
    // let (_vkey, _output, proof) = sp1_args.request_p256_proof().await.unwrap();

    // println!("Proof: {}", hex::encode(&proof));

    let proof = hex::decode("a4594c5912a8ae3e9beedcc567e019c042900a32079b4e708c9249f63fc30fbbb37ca2260ecf7555eafff6c2087c5de5da5b276074ceeaab99a004b0c5e3706b46afbe9715a6f3ce698cce83c0ff1db24fb357ac678fb8046b3445208ec6691667165899008b1c59ce9a34af2b8c6430ff642c70ccd29897981eec72ebd1c15365b8d34a2a7ababf0d0a7a78fc1a429e285db7c8dc64f603cfafaf56d230da36f750e96b080402970ebe78464c2b7b40509834e726d7636d1e76add24fdcd442c39d549505cc546e6ab368e1123ff12afab22c2004294a0f6a0b5aa56bd16b6c61517c981e7b9c3fc370b3b6250cb3c2680fae9dd2efdf1ca84d629150027241096cdaf2").unwrap();

    let ca_type = CertificateAuthority::SIGNING;

    let _tx = client
        .upsert_pcs_certificate(
            data_buffer_pubkey,
            TEST_ZKVM_VERIFIER_PUBKEY,
            ca_type,
            ZkvmSelector::Succinct,
            proof,
        )
        .await
        .unwrap();

    let (_, pcs_cert) = client.get_pcs_certificate(ca_type, false).await.unwrap();
    assert_eq!(pcs_cert, pcs_cert_data);
}

pub(crate) async fn test_pcs_platform_certificate_upsert(sdk: &Sdk<Arc<Keypair>>) {
    let client = sdk.pccs_client();
    let pcs_cert_data = include_bytes!("../../data/platform.der").to_vec();
    let data_buffer_pubkey = client
        .upload_pcs_data(false, pcs_cert_data.as_slice(), None)
        .await
        .unwrap();

    // let (_, issuer_der) = client
    //     .get_pcs_certificate(CertificateAuthority::ROOT, false)
    //     .await
    //     .unwrap();

    // let sp1_args = SP1RequestArguments {
    //     input_type: EcdsaZkVerifyInputType::X509,
    //     subject_data: pcs_cert_data.clone(),
    //     issuer_raw_der: issuer_der,
    // };
    // let (_vkey, _output, proof) = sp1_args.request_p256_proof().await.unwrap();

    // println!("Proof: {}", hex::encode(&proof));

    let proof = hex::decode("a4594c5902e84f5dc0d66da9099dccbd20d2d62b74b0c39aadca83e1e3528418739982282a134ec229592b7ac58beddcb1ab46817ce0fdbd70aeb7a73a149c9d5830ea960b6243e50b2f1213aab8461e7d61aa967caa3e13655d352baf722ebd3f598dfc22c7280c0f8bb0d189a68bba8dd2b21c96698c15d37e1626f5102c68fd39e78b2f772b2147831c2ef2c82495f06f5c93c42758b0944660736976dec742c62676047bf5ae09f20a8a5ce31a8001e855af9cfb35b88fabae9fbd96d5fa4c7ab00001f9da9eeb690f3a9c6159144f9c2621931eb85e1afe4c668a3c22aeef9cd28108a28d9a2ced03efd8c3f2bf89c1aaea95ec7ecfe30e2700282148ea4e75e372").unwrap();

    let ca_type = CertificateAuthority::PLATFORM;

    let _tx = client
        .upsert_pcs_certificate(
            data_buffer_pubkey,
            TEST_ZKVM_VERIFIER_PUBKEY,
            ca_type,
            ZkvmSelector::Succinct,
            proof,
        )
        .await
        .unwrap();

    let (_, pcs_cert) = client.get_pcs_certificate(ca_type, false).await.unwrap();
    assert_eq!(pcs_cert, pcs_cert_data);
}

pub(crate) async fn test_pcs_platform_crl_certificate_upsert(sdk: &Sdk<Arc<Keypair>>) {
    let client = sdk.pccs_client();
    let pcs_crl_data = include_bytes!("../../data/pck_platform_crl.der").to_vec();
    let data_buffer_pubkey = client
        .upload_pcs_data(true, pcs_crl_data.as_slice(), None)
        .await
        .unwrap();

    let ca_type = CertificateAuthority::PLATFORM;

    // let (_, issuer_der) = client.get_pcs_certificate(ca_type, false).await.unwrap();

    // let sp1_args = SP1RequestArguments {
    //     input_type: EcdsaZkVerifyInputType::CRL,
    //     subject_data: pcs_crl_data.clone(),
    //     issuer_raw_der: issuer_der,
    // };
    // let (_vkey, _output, proof) = sp1_args.request_p256_proof().await.unwrap();

    // println!("Proof: {}", hex::encode(&proof));

    let proof = hex::decode("a4594c5900a97d99eef2dc16648702675e381f8c1dd8bac692e873edb1d630118f6918ba06f7622ffa00481ea281e07c50d82d0db67969f0c2b6b7f06c1c15bdeb12f89d0c3f4ec95327ae8c99e53839d8b87ff9c22313fd3ff834d247886d1b9e73e03a1e4c314505b769185a660745ca96de243a1fd1f0ebee1e8426982ec1234f02a22ce5bdd8ae077d683ec9205bc78887b5c8f3a292e38c6bcd6ed20f507200343b089235a0c85cd460b61a4a68a3ab58ea822d053bd7430922269365927bfff6dc1516a93d06fbd1d8b36c3e66dd4a9810fd6b3780bb6a077d6cfabec528a7040c2b357978b63c5ffb33fec56f1025e6a3e65d1362d8eea77a728d5672be05245b").unwrap();

    let _tx = client
        .upsert_pcs_crl(
            data_buffer_pubkey,
            TEST_ZKVM_VERIFIER_PUBKEY,
            ca_type,
            ZkvmSelector::Succinct,
            proof,
        )
        .await
        .unwrap();

    let (_, pcs_crl) = client.get_pcs_certificate(ca_type, true).await.unwrap();
    assert_eq!(pcs_crl, pcs_crl_data);
}
