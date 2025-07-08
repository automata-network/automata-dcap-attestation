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

    let (_, issuer_der) = client.get_pcs_certificate(ca_type, false).await.unwrap();

    let sp1_args = SP1RequestArguments {
        input_type: EcdsaZkVerifyInputType::CRL,
        subject_data: pcs_crl_data.clone(),
        issuer_raw_der: issuer_der,
    };
    let (_vkey, _output, proof) = sp1_args.request_p256_proof().await.unwrap();

    println!("Proof: {}", hex::encode(&proof));

    // let proof = hex::decode("05a0b21045314d17253c62e4fbe6b58a726b32909ec0d160ff55fd6c710c74d912fdcfdc480d38e491be162ccab697533effe81c6ef20dcccad92eee7d3e9ab53054fa108cd15e9d50a2e10567d273ea1be5328d8a60003b973a763c02eb9d7f0d4e19d1c65fc76cee328b9d81b20c56f51cea39a873bba6f6d04be6f9c5aa1c1663ac45ff068cb126ea14ef154b55006257567ab03464eb5f09e2a12d05e5e22d0d0a48dd735c9d2956a058d503fb91541a34cee04328009cd6be06f9e87e0c143a1966fd18eca223be0f49af7a5dbbc5710bb6fc057d7883ce3a5a913028233016a41d232d64c3d708367998e7a7ce230acd702037ce558d9fd88a044eb53c").unwrap();

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

    let (_, issuer_der) = client
        .get_pcs_certificate(CertificateAuthority::ROOT, false)
        .await
        .unwrap();

    let sp1_args = SP1RequestArguments {
        input_type: EcdsaZkVerifyInputType::X509,
        subject_data: pcs_cert_data.clone(),
        issuer_raw_der: issuer_der,
    };
    let (_vkey, _output, proof) = sp1_args.request_p256_proof().await.unwrap();

    println!("Proof: {}", hex::encode(&proof));

    let proof = hex::decode("29ffe37a93c60d99ecc23cba9985a9f145b52738597367c1cd3611985a08d13a26f60617877a6bd3e45eea78012bf732449604aff11ca62f93efdb356623a77f15e5485de7610eaf6955cf69fff62e329653a90c5ce16b691883e5c4c3510d910541f9f791e9e0814d2988bafe904b9d37a14edece2f9a777b6e35018444cc6b194eb05ff81c8c26f70df82847e9287e7dd9655534d4e577fb68b2244b92c18b12d62d8bbfb36056f1681c2443b764f361505a63ff4d20c12442a339cc1ae74326f820b091bb842a52da4910ba2d55e6eeb7453a1f13eb7353f8a2c58488f22f14d6e1870817f34e90ed521b645661c7fbfdaf88ba645127c8013019afcd5fde").unwrap();

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

    let (_, issuer_der) = client
        .get_pcs_certificate(CertificateAuthority::ROOT, false)
        .await
        .unwrap();

    let sp1_args = SP1RequestArguments {
        input_type: EcdsaZkVerifyInputType::X509,
        subject_data: pcs_cert_data.clone(),
        issuer_raw_der: issuer_der,
    };
    let (_vkey, _output, proof) = sp1_args.request_p256_proof().await.unwrap();

    println!("Proof: {}", hex::encode(&proof));

    // let proof = hex::decode("26d698a04ac532666cdd9969237a7b531ff19eef45318dd4655b575ff2fcd1d42c4b711da166c7594e132d6ac9aae65ed9ebc1a9865fabba5d8e2b97dadb629e0f024805f98ddcd9de19eb963c2cf3fdf6779778281bfe21d87d1fdd20cae68d18637399a9186637aa6dae5754ab645a95d747429228d0fca1133adbe1bfe8e124018a42002b6115ef842c07f142e3a6c39c85f398bd34f571cb8237b286e9032dd476223c9deede3f8c023df70b93948f6808ebe47812e4dea44a7a56fcf5fd1d02e0e32936dbdbfe88cc8f3f7e43cdc0e20cf7e7f15be39f65ea7e41e2b2ed2b7f4152645c1f2ecbd3e16f02680a807d28a783bb72709b399a435400e518bc").unwrap();

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

    let (_, issuer_der) = client.get_pcs_certificate(ca_type, false).await.unwrap();

    let sp1_args = SP1RequestArguments {
        input_type: EcdsaZkVerifyInputType::CRL,
        subject_data: pcs_crl_data.clone(),
        issuer_raw_der: issuer_der,
    };
    let (_vkey, _output, proof) = sp1_args.request_p256_proof().await.unwrap();

    println!("Proof: {}", hex::encode(&proof));

    // let proof = hex::decode("0b8ee0abcd9463d679925e6535b0ade6151e11fde47804512e1e2dc3da6ac65a2160916d5ddcbeb0684b66d13d6b6034f3099499b783682f69aa959ed57b37522e716f59c6fdd9018becce962d8ca2e4a973f7466552038046ce6c8793ef22aa1899ca97da20892126be28839ea134b3730f3e928e83bb44acf6733cd356cc8e0b2a25d93e6cc89ca2c24fa8746e413afec061c4d8e80b8016bbba3597b71517219a0b2e2384013b9e6b9bc915a430b76fc0fbe15690f746fb5bd5155ab5ba970ef9fd81e4535b6b39d2694dac62379de02bb21638c4b4f478fd8e8e42a47a5c262dfb437aeacfded29d316b8def0aac3014043ba041d10827be6ceedf08e744").unwrap();

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
