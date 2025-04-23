use sdk::CertificateAuthority;
use sdk::automata_on_chain_pccs::types::ZkvmSelector;
use solana_zk_tests::zkvm::risc0::deploy_risc0_groth16_verifier;
use anchor_client::solana_sdk::commitment_config::CommitmentConfig;
use anchor_client::solana_client::nonblocking::rpc_client::RpcClient;
use crate::TEST_RISC0_VERIFIER_PUBKEY;

#[tokio::test]
pub async fn test_pcs_root_ca_upsert() {
    use super::*;

    let signer = get_signer();
    let sdk = sdk::Sdk::new(get_signer(), None);
    let client = sdk.pccs_client();
    let root_cert_data = include_bytes!("../../data/root.der").to_vec();
    let num_chunks = sdk::get_num_chunks(root_cert_data.len(), 512);
    let data_buffer_pubkey = client
        .init_data_buffer(root_cert_data.len() as u32, num_chunks)
        .await
        .unwrap();
    client
        .upload_chunks(data_buffer_pubkey, &root_cert_data, 512)
        .await
        .unwrap();

    let rpc_client = RpcClient::new_with_commitment(
        String::from("http://localhost:8899"),
        CommitmentConfig::confirmed(),
    );
    if rpc_client.get_account(&TEST_RISC0_VERIFIER_PUBKEY).await.is_err() {
        deploy_risc0_groth16_verifier(
            signer.as_ref(), 
            &rpc_client
        ).await.unwrap();
    }

    let ca_type = CertificateAuthority::ROOT;
    let _tx = client
        .upsert_pcs_certificate(
            ca_type,
            false,
            data_buffer_pubkey,
            ZkvmSelector::RiscZero,
            TEST_RISC0_VERIFIER_PUBKEY,
        )
        .await
        .unwrap();

    let (_, pcs_cert) = client.get_pcs_certificate(ca_type, false).await.unwrap();
    let actual_ca_type: CertificateAuthority = pcs_cert.ca_type.into();
    assert_eq!(actual_ca_type, ca_type);
    assert_eq!(pcs_cert.cert_data, root_cert_data);
}

// #[tokio::test]
// async fn test_pcs_signing_certificate_upsert() {

//     let client = sdk::PccsClient::new(get_signer()).unwrap();
//     let pcs_cert_data = include_bytes!("../../data/signing_cert.pem").to_vec();
//     let num_chunks = sdk::get_num_chunks(pcs_cert_data.len(), 512);
//     let data_buffer_pubkey = client.init_data_buffer(pcs_cert_data.len() as u32, num_chunks).await.unwrap();
//     client.upload_chunks(data_buffer_pubkey, &pcs_cert_data, 512).await.unwrap();

//     let ca_type = CertificateAuthority::SIGNING;

//     let _tx = client.upsert_pcs_certificate(ca_type, false, data_buffer_pubkey).await.unwrap();

//     let pcs_cert = client.get_pcs_certificate(ca_type, false).await.unwrap();

//     let actual_ca_type: CertificateAuthority = pcs_cert.ca_type.into();
//     assert_eq!(actual_ca_type, ca_type);
//     assert_eq!(pcs_cert.cert_data, pcs_cert_data)
// }

// #[tokio::test]
// async fn test_pcs_platform_crl_certificate_upsert() {
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

// #[tokio::test]
// async fn test_pcs_root_crl_certificate_upsert() {
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
