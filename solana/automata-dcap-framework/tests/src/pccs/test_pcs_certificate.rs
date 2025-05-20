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

    let proof = hex::decode("1c7d22d8b0ba7a0167f7fec39f98572c8ebebe37b1a3ff43b2c77d088696a5161bbb2d32be7558c6ec685666b905db682ebb31a43d644470f333c8e10383197610376ff0afd2fbd292b6bb882a1c9dc8b346d49624a4b4962aa271d375c6023d0c3a989a16b4cd88df26016a51fdb5390efb637af3bcb1e339a4f20ddf0489201b4c2348c22b8593ce2da29861b5ed452f9b81d8105393edf32eace7f056a0551380193f4ac908bf8677c80774dab2b73523569ab2d7d9d60a1492df23d512170274f255235648a008c7b1602172360023d16e3f30c93486a927fd8c95eec1de0c2718256273f6e1af883866f9d5226d3f4a64a292f3bfb918661d574289b9ad").unwrap();

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

    // let (_image_id, journal, proof) = request_ecdsa_verify_proof(
    //     EcdsaZkVerifyInputType::CRL,
    //     pcs_crl_data.as_slice(),
    //     issuer_der.as_slice()
    // )
    // .await
    // .unwrap();

    let proof = hex::decode("05a0b21045314d17253c62e4fbe6b58a726b32909ec0d160ff55fd6c710c74d912fdcfdc480d38e491be162ccab697533effe81c6ef20dcccad92eee7d3e9ab53054fa108cd15e9d50a2e10567d273ea1be5328d8a60003b973a763c02eb9d7f0d4e19d1c65fc76cee328b9d81b20c56f51cea39a873bba6f6d04be6f9c5aa1c1663ac45ff068cb126ea14ef154b55006257567ab03464eb5f09e2a12d05e5e22d0d0a48dd735c9d2956a058d503fb91541a34cee04328009cd6be06f9e87e0c143a1966fd18eca223be0f49af7a5dbbc5710bb6fc057d7883ce3a5a913028233016a41d232d64c3d708367998e7a7ce230acd702037ce558d9fd88a044eb53c").unwrap();

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

    let proof = hex::decode("0b952368b183786243761a55a7d51a51ad2820ff640868550c7c50ba210e25640839782151ddebaf3a24ce0aa62c0187e8cca091fe6c594cf2d5c490007ee9b6075b0439c5549282a9a00a5142a0c0dd312526c866d4558d7cf5e0787a620a5d2fbca6f06d4bdd09bd34e9e8b6c9aa6e230a0106c50f8734eede0bc744a28633216bb1878cb2b23807fba055082079137e52ea094938d992c5e7cd089817e2e305fd30ea2e9faa49522d62a1ac06c5909c01fe0bfe9408f9fdf4a9c2a9dba29424439c6c420b5400dcb1de43393e4bbcb783d5f7b90806b8b7fe25135f52f7381d1624e46b8c280da80deb79228308cfe2eaa2fad3ca7f67620fab671332976e").unwrap();

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

    let proof = hex::decode("26d698a04ac532666cdd9969237a7b531ff19eef45318dd4655b575ff2fcd1d42c4b711da166c7594e132d6ac9aae65ed9ebc1a9865fabba5d8e2b97dadb629e0f024805f98ddcd9de19eb963c2cf3fdf6779778281bfe21d87d1fdd20cae68d18637399a9186637aa6dae5754ab645a95d747429228d0fca1133adbe1bfe8e124018a42002b6115ef842c07f142e3a6c39c85f398bd34f571cb8237b286e9032dd476223c9deede3f8c023df70b93948f6808ebe47812e4dea44a7a56fcf5fd1d02e0e32936dbdbfe88cc8f3f7e43cdc0e20cf7e7f15be39f65ea7e41e2b2ed2b7f4152645c1f2ecbd3e16f02680a807d28a783bb72709b399a435400e518bc").unwrap();

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

    let proof = hex::decode("0b8ee0abcd9463d679925e6535b0ade6151e11fde47804512e1e2dc3da6ac65a2160916d5ddcbeb0684b66d13d6b6034f3099499b783682f69aa959ed57b37522e716f59c6fdd9018becce962d8ca2e4a973f7466552038046ce6c8793ef22aa1899ca97da20892126be28839ea134b3730f3e928e83bb44acf6733cd356cc8e0b2a25d93e6cc89ca2c24fa8746e413afec061c4d8e80b8016bbba3597b71517219a0b2e2384013b9e6b9bc915a430b76fc0fbe15690f746fb5bd5155ab5ba970ef9fd81e4535b6b39d2694dac62379de02bb21638c4b4f478fd8e8e42a47a5c262dfb437aeacfded29d316b8def0aac3014043ba041d10827be6ceedf08e744").unwrap();

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
