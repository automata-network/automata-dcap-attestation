use crate::TEST_RISC0_VERIFIER_PUBKEY;
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
        .upload_pcs_data(root_cert_data.as_slice(), None)
        .await
        .unwrap();

    let (_image_id, _journal, proof) = request_ecdsa_verify_proof(
        EcdsaZkVerifyInputType::X509,
        root_cert_data.as_slice(),
        root_cert_data.as_slice()
    )
    .await
    .unwrap();

    let ca_type = CertificateAuthority::ROOT;
    let _tx = client
        .upsert_pcs_certificate(
            data_buffer_pubkey,
            TEST_RISC0_VERIFIER_PUBKEY,
            ca_type,
            false,
            ZkvmSelector::RiscZero,
            proof,
        )
        .await
        .unwrap();

    let (_, pcs_cert) = client.get_pcs_certificate(ca_type, false).await.unwrap();
    assert_eq!(pcs_cert, root_cert_data);
}

pub(crate) async fn test_pcs_signing_certificate_upsert(sdk: &Sdk<Arc<Keypair>>) {
    let client = sdk.pccs_client();
    let pcs_cert_data = include_bytes!("../../data/signing.der").to_vec();
    let data_buffer_pubkey = client
        .upload_pcs_data(pcs_cert_data.as_slice(), None)
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
    )
    .await
    .unwrap();

    let ca_type = CertificateAuthority::SIGNING;

    let _tx = client
        .upsert_pcs_certificate(
            data_buffer_pubkey,
            TEST_RISC0_VERIFIER_PUBKEY,
            ca_type,
            false,
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
        .upload_pcs_data(pcs_cert_data.as_slice(), None)
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
    )
    .await
    .unwrap();

    let ca_type = CertificateAuthority::PLATFORM;

    let _tx = client
        .upsert_pcs_certificate(
            data_buffer_pubkey,
            TEST_RISC0_VERIFIER_PUBKEY,
            ca_type,
            false,
            ZkvmSelector::RiscZero,
            proof,
        )
        .await
        .unwrap();

    let (_, pcs_cert) = client.get_pcs_certificate(ca_type, false).await.unwrap();
    assert_eq!(pcs_cert, pcs_cert_data);
}

// pub(crate) async fn test_pcs_platform_crl_certificate_upsert() {
//     let client = sdk::PccsClient::new(get_signer()).unwrap();
//     let pcs_cert_data = include_bytes!("../../data/pck_platform_crl.der").to_vec();
//     let num_chunks = sdk::get_num_chunks(pcs_cert_data.len(), 512);
//     let data_buffer_pubkey = client.init_data_buffer(pcs_cert_data.len() as u32, num_chunks).await.unwrap();
//     client.upload_chunks(data_buffer_pubkey, &pcs_cert_data, 512).await.unwrap();

//     let ca_type = CertificateAuthority::PLATFORM;

//     let _tx = client.upsert_pcs_certificate(ca_type, true, data_buffer_pubkey).await.unwrap();

//     let pcs_cert = client.get_pcs_certificate(ca_type, true).await.unwrap();

//     let actual_ca_type: CertificateAuthority = pcs_cert.ca_type.into();
//     assert_eq!(actual_ca_type, ca_type);
//     assert_eq!(pcs_cert.cert_data, pcs_cert_data)
// }

// pub(crate) async fn test_pcs_root_crl_certificate_upsert() {
//     let client = sdk::PccsClient::new(get_signer()).unwrap();
//     let pcs_cert_data = include_bytes!("../../data/intel_root_ca_crl.der").to_vec();
//     let num_chunks = sdk::get_num_chunks(pcs_cert_data.len(), 512);
//     let data_buffer_pubkey = client.init_data_buffer(pcs_cert_data.len() as u32, num_chunks).await.unwrap();
//     client.upload_chunks(data_buffer_pubkey, &pcs_cert_data, 512).await.unwrap();

//     let ca_type = CertificateAuthority::ROOT;

//     let _tx = client.upsert_pcs_certificate(ca_type, true, data_buffer_pubkey).await.unwrap();

//     let pcs_cert = client.get_pcs_certificate(ca_type, true).await.unwrap();

//     let actual_ca_type: CertificateAuthority = pcs_cert.ca_type.into();
//     assert_eq!(actual_ca_type, ca_type);
//     assert_eq!(pcs_cert.cert_data, pcs_cert_data)
// }
