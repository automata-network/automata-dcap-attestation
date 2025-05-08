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

    let (_image_id, _journal, proof) = request_ecdsa_verify_proof(
        EcdsaZkVerifyInputType::X509,
        root_cert_data.as_slice(),
        root_cert_data.as_slice(),
        None
    )
    .await
    .unwrap();

    // let proof = hex::decode("").unwrap();

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

    let (_, issuer_der) = client
        .get_pcs_certificate(ca_type, false)
        .await
        .unwrap();

    let (_image_id, _journal, proof) = request_ecdsa_verify_proof(
        EcdsaZkVerifyInputType::CRL,
        pcs_crl_data.as_slice(),
        issuer_der.as_slice(),
        None
    )
    .await
    .unwrap();

    // let proof = hex::decode("").unwrap();

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

    let (_, issuer_der) = client
        .get_pcs_certificate(CertificateAuthority::ROOT, false)
        .await
        .unwrap();

    let (_image_id, _journal, proof) = request_ecdsa_verify_proof(
        EcdsaZkVerifyInputType::X509,
        pcs_cert_data.as_slice(),
        issuer_der.as_slice(),
        None
    )
    .await
    .unwrap();

    // let proof = hex::decode("04729ae5819c1e02cfea93b962485cd219c5e31d9ae13c86a59da87c174c2c4d28602f51aba4371302ba96649db59ba07bd19d170333472cbe69955e3be7abff2fb147ab6f0465067e17aa86afc573871e7bb2141d91c8266d7af662b28bc1711d90357c649239dd0c4aef4b9cdca3b1b0fc237f5c5357ca808a2cf6756a1f6b27c80ec014e9c460c4c4b2c59b65f12cfbcc7b88cf5230524a383f6165502db624c3bd166393f9c67351ebbdc2e59844c5c41cbdd9c89715683d8168e5238bec28a78ce9a5dd62774a8e8ace57a4f5182f370e833042523ac8e39e3f3ae3c6171db2b584e5cbedcf8de324ee0a857b70b7ba1ce1ae7cd18bab42c4dcc9f34117").unwrap();

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

    let (_, issuer_der) = client
        .get_pcs_certificate(CertificateAuthority::ROOT, false)
        .await
        .unwrap();

    let (_image_id, _journal, proof) = request_ecdsa_verify_proof(
        EcdsaZkVerifyInputType::X509,
        pcs_cert_data.as_slice(),
        issuer_der.as_slice(),
        None
    )
    .await
    .unwrap();

    // let proof = hex::decode("").unwrap();

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

    let (_, issuer_der) = client
        .get_pcs_certificate(ca_type, false)
        .await
        .unwrap();

    let (_image_id, _journal, proof) = request_ecdsa_verify_proof(
        EcdsaZkVerifyInputType::CRL,
        pcs_crl_data.as_slice(),
        issuer_der.as_slice(),
        Some(ROOT_CRL_BYTES)
    )
    .await
    .unwrap();

    // let proof = hex::decode("").unwrap();

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
