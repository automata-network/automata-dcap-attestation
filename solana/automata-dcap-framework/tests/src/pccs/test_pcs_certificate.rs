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

    let proof = hex::decode("25c3f8a629f77e4459411f01abfc3ff80ea32de32c5cb4dd804f9ce427242dec07d079b9cebadb6e07355a83d93e06d5644a50cb58fe0fb1bc1ae41e143f72692097790cf34556a5516b0ad9e22cc8e52aacca030cb8d941521fddc27967ac651ce26c4b4a154b85d56da866dfadf7a5c0a30da1c79d0507a6507c39b16787ba25555f1ab83981592ec493284fe868624186bce115c36ba13d70b17a7877393311499bf2eabc3fcab9fc396fc2475748ffd9566cb65e3e2350eb694a8991ce8f050011665c29d4ce1d9ced4ec69fd01216bdbcd176a96a5777849c466a6570022270d042c755a9a0deaee9d60265593fdefbc85c6ff0ca9589eb666980960683").unwrap();

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

    let proof = hex::decode("0e8a94143798f78584bb383becebe46fa7377f1ed89a32eef43769f6f9f70c122e9d3f6b7289caaa6ded733793bd1891bc82585b4e66bdabb8b79f7f8f44d76b182c35fdabd97ec35709a2dabd89d533450b24729e9778534b0a99bcf64e43d302d3f34ffed385976ec8b16b44cfdfbb0fcb9e6064c7fdc1a46b6b0d099747d4117db32faa576de81f6ee5bf2f3785e85da22f56e6be53fb2aa71943afe6657c0fdc7a177d5a19070a794398736880e14849941611c3525cae899ee6ec0218a02aa455bb3cbe7f3fae1887a94bc0e603ee65a589e15331a94435b5912e84198924c166501664393153c3f26bb4bfa15a59f6a3b004097a1ec08d3bca5fcbfea0").unwrap();

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

    let proof = hex::decode("2f6f5b29ce65cb1ec20311b47c028a141588a4a025b62d8e492fd67ec3393c3d2bb4f8e1631da4bbf89564a71fe926254779e0d93b05ac6ce06afbb77f6148e6293c486aa0c99f2b23770bd31c696bc27b3eba46bb0e8b2132d6ba6eff24d1860524ab6b757987f4226bfae811946b5632fb2b6f260733d7b9f89a7db1e893cb22a8c0777451a2eb177b3eedc9625e3d72111f6d5ae4b935199fd14f7d368f08267eb89e949a458b04ae5314a3a5273f085684bd93ae621e4b40ef6a6febfe9625f63109d94f67d4f03c7c17dcb3a5ffc74a1a460c8ae0279379952439795de92056c8c93d98e335ba4cc0aee5e377099becb8b27a0315f4d87ba4ea9c1e0ba9").unwrap();

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

    let proof = hex::decode("07571e91cd6b08bc333429c084e90f4df0bc7115920316ac20e6a29b6356f4552e2aff254e9e7e9d9710aa5e4d950f9f1d8de573e2424c6a816984231cfc982e20cf985926820b4bf3a31762f7f18aeb949c760d10b0ca0de60b9be6a1c574cc0b8ebeff13228616bbddac2a9307a043e5dca8b63638c123709dfdba1a23780c038453bacf844017364a144969ce0f5c9469af6fcfbf9a5bd1ab9b031fbe297c18834dd49cd53de777b90b59c45eb34605b787b6f1b5cf2bd4e828f926412f7c2b1be9c2490171bc2609e16cda9e8c6a53d004b695a18392d7c022c236bd2ce10beebc40c78d39e27152da22e27b18785f733d956a091fa7cb8104a4e6fe4a8e").unwrap();

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

    let proof = hex::decode("0fed9ebec9c1cf2eb02fd9698757efdbab9e8e4b79768fdfb2a09122ee4dfbe62856dd8ffa444abb5f3696aff2b051038b6c47426a0ac500cf167e1832997b9a1a9e1e6c1c854e9a89fbe30c3539ae0f41a856900a8f9ca0de2b0fd09a29ad5a0ed14e234d346ee23c35fb49ab0f50202521b6b845867bc3fac17471def76d33044793b22f537881b477487380b2528b11131f804a982999f737e7fed872c697267cfece1beb0de09daaa1111270023a8b47e1d96ba0309415165cf7acf6cf32067aa42c40b283f41b8594bc542be0d74778ad713ecd30069c2ce3f74bd1e4fd2786f9aa481f7b9e799c583f4c3549335dbd0cf966f49bb1a26ac0a73937e86b").unwrap();

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
