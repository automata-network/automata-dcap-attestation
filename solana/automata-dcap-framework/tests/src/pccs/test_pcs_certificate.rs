use crate::{ROOT_CRL_BYTES, TEST_RISC0_VERIFIER_PUBKEY};
use anchor_client::solana_sdk::signer::keypair::Keypair;
use sdk::Sdk;
use sdk::models::CertificateAuthority;
use sdk::pccs::automata_on_chain_pccs::types::ZkvmSelector;
use sdk::pccs::{EcdsaZkVerifyInputType, request_ecdsa_verify_proof};
use std::sync::Arc;

pub(crate) async fn test_pcs_root_ca_upsert(sdk: &Sdk<Arc<Keypair>>) {
    let client = sdk.pccs_client();
    let root_cert_data = include_bytes!("../../data/root.der").to_vec();
    let data_buffer_pubkey = client
        .upload_pcs_data(false, root_cert_data.as_slice(), None)
        .await
        .unwrap();

    // let (_image_id, journal, proof) = request_ecdsa_verify_proof(
    //     EcdsaZkVerifyInputType::X509,
    //     root_cert_data.as_slice(),
    //     root_cert_data.as_slice(),
    // )
    // .await
    // .unwrap();

    let proof = hex::decode("2aae1b9978dc968eb9b6c8d2dc1c82b8390a359d7c08a64dcc42f745a7d0fcbb224149e9e01aca988191c5fa95ce1d45d9a23604bce6302bd7f31e47f275519a29ba0209549c345776b3d6603defaf39febd4fa538ec97c8377551bb9905c07b02e1f239dab656c63f68327ad3aa541b20e4329256778c5e303d8df977f6a5d502a399a4071fc4a782ff4df215f314a4a81bb199dfbcd4fdfdeed63e2c3312d814c4ebd8b5985a42f2ac36f7079d6a367ea35bc2ab5841a0150b223d093775a62b6b71eeb7a2da26ee9f6c870a44fea9ff16208d0d89483a08f129525664dd40099651020f0bf51a000b2ba2b8c52c9bf147a606cafddbcdde17059959e89452").unwrap();

    let ca_type = CertificateAuthority::ROOT;
    let _tx = client
        .upsert_pcs_certificate(
            data_buffer_pubkey,
            TEST_RISC0_VERIFIER_PUBKEY,
            ca_type,
            ZkvmSelector::RiscZero,
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

    // let (_, issuer_der) = client
    //     .get_pcs_certificate(ca_type, false)
    //     .await
    //     .unwrap();

    // let (_image_id, _journal, proof) = request_ecdsa_verify_proof(
    //     EcdsaZkVerifyInputType::CRL,
    //     pcs_crl_data.as_slice(),
    //     issuer_der.as_slice()
    // )
    // .await
    // .unwrap();

    let proof = hex::decode("2999bbedfe80d3905d6deef9a114dbcba7cab1bea31039fcd0546a069ce51e71096e36fec482a03174b48fe14995b870de2a9675cf9cff5ea2e5ceedae58b4bc1b90c61a783e0bfadb44b78a46f14d5ea221762e83c5114972143020fee9dc172561b7c6c1e4348b4d28bc339cdcbeb94849a17c2e6f9b6bb9873aa56ee29ded2980fc5e00bfdb761ecaffa2655f4c1bd2c32155db1d9d66b12af72b957781b22d430ec1e5455a0add24164c77feab64ae7081d05872d40d30ab8d917ed8b7d80d2b2bada2d277173ab1a82c593d64f157e9aa18bbafef5cf1b6af7283ca71212524183806dfacd44cf67c7d53a70f298a6f79d1b7fb390eb5806f4f6b30f457").unwrap();

    let _tx = client
        .upsert_pcs_crl(
            data_buffer_pubkey, 
            TEST_RISC0_VERIFIER_PUBKEY, 
            ca_type, 
            ZkvmSelector::RiscZero, 
            proof
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

    // let (_image_id, _journal, proof) = request_ecdsa_verify_proof(
    //     EcdsaZkVerifyInputType::X509,
    //     pcs_cert_data.as_slice(),
    //     issuer_der.as_slice()
    // )
    // .await
    // .unwrap();

    let proof = hex::decode("099003a0bffb7209f74bab0b47844196910a1370763aff317cc131ef92fd288c238baa6e35eb1a1a58a0cc615eb329445ecdb15af5ce9f04c9ec06ff534ba70a1bddc801a842b562a3a102f52b22ce15c3611b353b3cf654c0a27dd529ce8beb1e6b69e1861ebd906e5050c3c8e110c7343b4c1d098f47a923df204acb64a40d02fb5ec3d93c98ef6f40b4c4e8348bb0e70d3e957a1c2c70a3cd72a0740e973c28cc12c5c42ce2fe046864781e2b090404da01b59604e9014c4e5ff5e9cfddc0108a586f2d1b0b48859106386632cbc84ce8e6544d8d62dd2fca46b32335d2c80cd93bbede859fe071091ebb6d7abedd72fddb6985ebb6b413e489cef5b3ded9").unwrap();

    let ca_type = CertificateAuthority::SIGNING;

    let _tx = client
        .upsert_pcs_certificate(
            data_buffer_pubkey,
            TEST_RISC0_VERIFIER_PUBKEY,
            ca_type,
            ZkvmSelector::RiscZero,
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

    // let (_image_id, _journal, proof) = request_ecdsa_verify_proof(
    //     EcdsaZkVerifyInputType::X509,
    //     pcs_cert_data.as_slice(),
    //     issuer_der.as_slice()
    // )
    // .await
    // .unwrap();

    let proof = hex::decode("258e65460f580d83576759fe6c603edb197139a66e21fbec2f251ef7440ff0ae2a194d95c83c36e26ac3b5018fb3be7141dd01f175651a6a291b12a101fabe2d052f12887aed399b13853c5a118b3fda9a4d2ff20209d9dc8d5b6c7b5c1fd1be0368a709bd92d9cbd26090e9b22bd526a0af073616a08a789c9b81130ba19a86138cdecec060aa145ce38aa88e783301c06b68fa4df36e3dd9000f521d743a311c7a69bd450899f3d8dcc4f030a0839d38e36718824aa2f994958155dd216ad823873ae68deeacf928fae5aaf23a45c1ce733e20550dd3eb7602609a259b7bf109478fd79108844bbc0d2dc62fe5a1aed3c9c5e1a5286013eb8dbfc825e86c47").unwrap();

    let ca_type = CertificateAuthority::PLATFORM;

    let _tx = client
        .upsert_pcs_certificate(
            data_buffer_pubkey,
            TEST_RISC0_VERIFIER_PUBKEY,
            ca_type,
            ZkvmSelector::RiscZero,
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

    // let (_, issuer_der) = client
    //     .get_pcs_certificate(ca_type, false)
    //     .await
    //     .unwrap();

    // let (_image_id, _journal, proof) = request_ecdsa_verify_proof(
    //     EcdsaZkVerifyInputType::CRL,
    //     pcs_crl_data.as_slice(),
    //     issuer_der.as_slice()
    // )
    // .await
    // .unwrap();

    let proof = hex::decode("01d0ad02c241f74313784305a5a6973f0939eef68041ef5f3ccd6d76908755fc0fecfdd39e3ab84048ed61d0328e18508c7ff4ba3f1b85d2427c4f3b51f85ee723c5ea8abcfdf7d060c897d7a283b24b3c5a30ed065467584bafd4c0fb419dd103491adbdcfe57a1d6bba1fb5c0081144351a213baf6678ca4ca64d819f3dcc3021b62208ae0b48e414ab7614e49d5d85909ce97f673a57b09e41055673449ff29fd49f24a40593e797cca849bef76a6691b41fef290a4276d46bef5a8bb85072f8836764d9107c6fae8f0844b5484da849208990ec671d8e327b9c1917074be00eeb4117783331264be849b631282cfaf9dec3651d77a6fe7e0b6cdd82a73a9").unwrap();

    let _tx = client
        .upsert_pcs_crl(
            data_buffer_pubkey, 
            TEST_RISC0_VERIFIER_PUBKEY, 
            ca_type, 
            ZkvmSelector::RiscZero, 
            proof
        )
        .await
        .unwrap();

    let (_, pcs_crl) = client.get_pcs_certificate(ca_type, true).await.unwrap();
    assert_eq!(pcs_crl, pcs_crl_data);
}
