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

    let proof = hex::decode("0e90f237b191ac24ce52a6f6a1abcfc325f221ef419cbd4b58f371b63109d42b2fc70ec51241d58cddd55887ff62e52ee59a9824cae821c2398c6f0dd97bb2621b53b506353100bd522924715fa203ef9fb72fbee7f39388bf5f2e2f87874b7417be640b0e4dc50ae3de889dfc3e4ad01640fe7d0b910e7dfe0d38fa2cde808e0392d86ec70f0f11b273ca89836f6c722cd3d7bc3f4245be5cb7f9bc34dfd66c1b911db8bb0775ca79557687df2f1a3c71df919218d8614c5538d10e8e78e38f04f1cb2242983d061deeb9f0d64892c13001cc9f3a46ac509edf8b748399a7a805b947c93ea2f61eb23517e56f3587a47351d7c4ec7fdaaa8005838f88722c0d").unwrap();

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

    let proof = hex::decode("0f088516b7cfeaeb6b3bef9f8d9dbbc44f9f45dfa2fafd0038c5da9c7c9ff2ca09e17f55aa384373dd5ee96c99ab0142f663225dd39cbd66242798b104b2429f109a851597c944349b871ea28fed08683598f6c82befe80ae615d7263a6c74b912a083067c59614b277e1eed32044139576d0cb96e21a446ffa206004f4a64e103ce6a34440bd248d895296d972675b9852239e4c037e5a3e30580349a61026f1fa1f196696c8dadacd778ca97602562d75416785413e35826532811c58d35740e6a2533ea35202d4def2119ae2c867b902f2d73241832add75728afccfe187c0e07a1ee02ad8895431501853d01ec2ce08de421248ff72c894eb9ff241774d4").unwrap();

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

    let proof = hex::decode("047aeb21374037d4ef1534c0cb9ed709e60603b711d36b46e4a73ec3a7b4e44228fe38a2e063439b455c964d41104b279e7c4ff0024ee8781cace13b38ecb45f244c55e3ad7926f5620e5036d1dde1fa82b4143cbff04acfb920cf9d63dda21a266a7df4393f13d324da7f78bd614e5804ca077a2a965f032b472248d2e169940d539f5f2bfd7cec1524c52495ed2e4e61043558e71eb26bd54878c67a5fb94f0b34b0006f41232e7df19667cd6cc084d5ad4f9dc458b0659835d059dda8cf4c0d70ce991cd4263034d146eb7d285c262acc17c2f5c2e599c0854449c695309c23a9b098b99dd9094b108ba63e59fb96a00c55d0cd68719a9afda93b0500980e").unwrap();

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

    let proof = hex::decode("1da26a0b8f8b7bb64633a7ea1daa4e03e0362071e78b8def464819314a4d2fb02b0398a3b95517b7a343c8dbd44de29c4e1ad25d8134bfbf715f7b64aafdbcbf2b81d02e4f4c2208477359dbb7874bf76fecf6b4cd09bfc187d1007f4999715719b116a69ce6d4bc1ab6c7381ae11f25d6530b2061cad993b43203cce2b62fc80efb6962bbadf48175d317c7e2fd7343785846b6713b8448afe1f611bec6dd081bd4fae2564e875341df5383e7f4f8755f4d2e2c0f87617323627aa42aa7dc5f10b85a22023036f5e6475b71af84fbd2facdabaf8325f9696bf29dd5f234370a2f106ecfd22d612af5d2e1cf6c43f6a8a771711be88dd72affbb459d5d0d283e").unwrap();

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

    let proof = hex::decode("2fbe2fcde9cc0da0ea3d1fb3ec3cf05c5a8f335084d3871d16582c54f4d6995f2e02f6945deae13545ef6e48ce36fd5721cf9de5b1af12f67f2ac2a71fbbd51b2537671fcec34a8194e4c94b8eb7ac1042138b78094f75fd2be14b81f9af787714f42c8479e79edee419ebe7d303c102977c34f468070aa68ae0fc305dc9792b19ec06ff7cbfdeb927084abc051aea70e9ef4a0a186695fbf366c16b0a90aee8067c1212da6216db5c1293abdf6dc487106657f3868886ea72eb3ba40df0f79a2904f0ff9ae0701144a91897caac28b892559760358f14aa8e14175dc130f0642e810dfc63488173af81e8f0575a85a35667b651ac1d2d8f63c9a04699791118").unwrap();

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
