use automata_on_chain_pccs::state::CertificateAuthority;

use crate::pccs::{PccsTestConfig, PccsTestHarness};



#[test]
fn test_pcs_crl_certificate_upsert() {
    let config = PccsTestConfig::default();
    let harness = PccsTestHarness::new(config);

    let pcs_cert_data = include_bytes!("../../data/signing_cert.pem").to_vec();
    let num_chunks = PccsTestHarness::get_num_chunks(pcs_cert_data.len(), 512);
    let data_buffer_pubkey = harness.init_data_buffer(pcs_cert_data.len() as u32, num_chunks).unwrap();
    harness.upload_chunks(data_buffer_pubkey, &pcs_cert_data, 512).unwrap();


    let ca_type = CertificateAuthority::SIGNING;

    let _tx = harness.upsert_pcs_certificate(ca_type, data_buffer_pubkey).unwrap();

    let pcs_cert = harness.get_pcs_certificate(ca_type).unwrap();

    assert_eq!(pcs_cert.ca_type, ca_type);
    assert_eq!(pcs_cert.cert_data, pcs_cert_data)
}
