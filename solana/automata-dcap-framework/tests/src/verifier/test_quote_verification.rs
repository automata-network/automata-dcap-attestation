use crate::verifier::{VerifierTestConfig, VerifierTestHarness};

#[test]
fn test_quote_tdx_verification() {
    let config = VerifierTestConfig::default();
    let harness = VerifierTestHarness::new(config);

    let quote_data = include_bytes!("../../data/quote_tdx.bin");

    let quote_buffer_pubkey = harness
        .init_quote_buffer(
            quote_data.len() as u32,
            VerifierTestHarness::get_num_chunks(quote_data.len(), 512),
        )
        .unwrap();

    harness
        .upload_chunks(quote_buffer_pubkey, quote_data, 512)
        .unwrap();

    harness.verify_quote(quote_buffer_pubkey).unwrap();
}
