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
    //     None
    // )
    // .await
    // .unwrap();

    let proof = hex::decode("1d73c105aedaf0d1bc48d0fdeb0d815d084e51a52b5839fc47bff694d197a1be2613d113d7cbd144c5336f8da67156a88fcb4b08484414fd98476e757292189e2fdc598670d88da82bf6569f79d0d1da9854161f0e086fdb04a8f228a02c60cb10a0ebda345dfbdc3278dd417c295bfb1ad4dbf5c01f27827cf75b1f0bbcf3832287242d4ebe9d938d9195215be3aa8971e3a84be858587e5c791e73c4c132e2269f82bf3a78f63c4946feeada5f753f2258c047861f3ca7e204726e75c3d05f2609aa070e5886a061f34f07fa420d2cb5b8bd4c32c0f61ba4ded33877a571642a88eae97dce31750f666e8adc1ad4852329b101a73e5413644e0b9e8fac2e5f").unwrap();

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
    //     issuer_der.as_slice(),
    //     None
    // )
    // .await
    // .unwrap();

    let proof = hex::decode("054c9c68e32ab179067952f986bd2e2b3e747855f502782e24b1f75ec72d3c5403ef393be8bf6ef92fb3f2bdcc41332019ddccc90bebdbe547ad3c55ed9451da265a71193e79715cbd5428d744e050d255f8ece6aa653cf3f144ee24f088572c1fc40ebf51c870e3fd3b479f6a56b2a225670f7acbfb8b34669224e8f8b6b3921395588d917ed908d0a47773cf6c3e001f5e3aa31fc80c61681565e78cbce5ee1896a548c9b5d2e975384c31b194236a86e3a974d0d137b6c1416d8ecfa83d582a6e9c221a9cf403fc53ba3caadfe1c683187efedff333739314bac29807ab121eeca0d5b2b4ec1737d0881cbde0063bf88aa0ad1976ed3a1e9189bad818e06f").unwrap();

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
    //     issuer_der.as_slice(),
    //     None
    // )
    // .await
    // .unwrap();

    let proof = hex::decode("08eb4835e12778876d1f2c818212a9cb7f5a34435a6422f22570d28ef84662102ee0ee3db706d149e235aea1945651148ec3cdc09fe7da2f23f346d407b96c4426fe70004a78dc20f4a36979cbcae4cc9cdb10bf1dd94dda309f9985cbd4cd7b1e18d21a36c0820924549e7a2ec0105a4b5aba0c0830821c2d111e97f38d59e6201932229fb00320a697187cb05400517c2593f5de4f02064413d11d26f0fb1b29be1527619ba51d970193fc1033878f77ab4c6e4b4b06e3043842f37b801c900ebc27913187963e78435f6c350355b858def70e536ddd4cd61ffcccf93ca19c0dc156ba347b9334ce20cba95697829c8b04b87c6ccec85598c805a4a2929a5c").unwrap();

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
    //     issuer_der.as_slice(),
    //     None
    // )
    // .await
    // .unwrap();

    let proof = hex::decode("1fdb70cff887af80abf5dc6f07a234af710a85c6d8850c078cc18038eb8f8d8f01091fd8ff6b825aeca863b0eb4f675a59e1d15ff2f9365dfc4f2eb92cfcae5301277327b0be4a540f78ed8abbab645008a4b8f1cdcd18e90c76c2a1c15fb8e40617257248bf2ba8c9eb777bb94f506de4519bb2979a88a5bafd5aaec0640e59054a22779bae7d0b17fcd4b156bc90308d9c0a9b4e0de9e126640764b82005d70f93fdb60bd6af243266bbb2afe2cfcb6221f5fefce80b068bdd722bff7dbbc4298ff6f00ab9dee8e57c1817f287fa665ec5bb1aba62deb47d9b2d1d5f11c78720fc677a531317bdfc203c01d0a26079c11bf6c2e1614d5d3d1b6d3164a77401").unwrap();

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
    //     issuer_der.as_slice(),
    //     Some(ROOT_CRL_BYTES)
    // )
    // .await
    // .unwrap();

    let proof = hex::decode("07249dba897043fd27a147e853cfc280d1d250f764d529c08487b156afacd7e905ebd0877bc682f59e573dcf2b753ad9a92851f2e25e1ea58d74800b1943dad225ae4fa0551a5afdd38b3d1a207c9367ee2b1a9ad997758123e9a95325f2f13326734875a9bb6e0370615c527b10f3bdd36fec933270de0bb6de7ee60f94a87c0db03366a8c03e8e02d913c323075256df298bb792c46ee2b40a85603ba67ba22abbc6bc0deb31d5e48960ba70922f9683d48f2a5f3f14f908899f982e16d1ba2ad103c51dcfb39664be1377089b241e87d81fb1f812dd76f5b96b6516653473230326e18ce562a1b77f04aba59a5e756dc04bf777f479b3e647044be9de80fd").unwrap();

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
