use automata_dcap_framework::state::DataBuffer;

use crate::verifier::{TestConfig, VerifierTestHarness};

#[test]
fn test_quote_tdx_with_chunks() {
    let config = TestConfig::default();
    let harness = VerifierTestHarness::new(config);

    let quote_data = include_bytes!("../../data/quote_tdx.bin");

    let quote_buffer_pubkey = harness
        .init_quote_buffer(
            quote_data.len() as u32,
            VerifierTestHarness::get_num_chunks(quote_data.len(), 512),
        )
        .unwrap();
    let quote_buffer_account = harness
        .get_account::<DataBuffer>(quote_buffer_pubkey)
        .unwrap();

    assert_eq!(quote_buffer_account.owner, harness.get_payer());
    assert_eq!(quote_buffer_account.total_size, quote_data.len() as u32);
    assert_eq!(quote_buffer_account.num_chunks, 16);
    assert_eq!(quote_buffer_account.chunks_received, 0);
    assert_eq!(quote_buffer_account.complete, false);

    harness
        .upload_chunks(quote_buffer_pubkey, quote_data, 512)
        .unwrap();

    // Fetch the quote buffer account again to verify the changes
    let quote_buffer_account = harness
        .get_account::<DataBuffer>(quote_buffer_pubkey)
        .unwrap();

    assert_eq!(quote_buffer_account.owner, harness.get_payer());
    assert_eq!(quote_buffer_account.total_size, quote_data.len() as u32);
    assert_eq!(quote_buffer_account.num_chunks, 16);
    assert_eq!(
        quote_buffer_account.chunks_received, 16,
        "Not all chunks were recorded"
    );
    assert_eq!(
        quote_buffer_account.complete, true,
        "Buffer should be marked complete"
    );

    // Verify data integrity
    assert_eq!(quote_buffer_account.data.len(), quote_data.len());
    assert_eq!(quote_buffer_account.data, quote_data, "Quote data mismatch");

    println!(
        "Successfully uploaded and verified quote data ({} bytes)",
        quote_data.len()
    );
}

#[test]
fn test_quote_sgx_with_chunks() {
    let config = TestConfig::default();
    let harness = VerifierTestHarness::new(config);

    let quote_data = include_bytes!("../../data/quote_sgx.bin");

    let expected_num_chunks = VerifierTestHarness::get_num_chunks(quote_data.len(), 512);
    let quote_buffer_pubkey = harness
        .init_quote_buffer(quote_data.len() as u32, expected_num_chunks)
        .unwrap();
    let quote_buffer_account = harness
        .get_account::<DataBuffer>(quote_buffer_pubkey)
        .unwrap();

    assert_eq!(quote_buffer_account.owner, harness.get_payer());
    assert_eq!(quote_buffer_account.total_size, quote_data.len() as u32);
    assert_eq!(quote_buffer_account.num_chunks, expected_num_chunks);
    assert_eq!(quote_buffer_account.chunks_received, 0);
    assert_eq!(quote_buffer_account.complete, false);

    harness
        .upload_chunks(quote_buffer_pubkey, quote_data, 512)
        .unwrap();

    // Fetch the quote buffer account again to verify the changes
    let quote_buffer_account = harness
        .get_account::<DataBuffer>(quote_buffer_pubkey)
        .unwrap();

    assert_eq!(quote_buffer_account.owner, harness.get_payer());
    assert_eq!(quote_buffer_account.total_size, quote_data.len() as u32);
    assert_eq!(quote_buffer_account.num_chunks, expected_num_chunks);
    assert_eq!(
        quote_buffer_account.chunks_received, expected_num_chunks,
        "Not all chunks were recorded"
    );
    assert_eq!(
        quote_buffer_account.complete, true,
        "Buffer should be marked complete"
    );

    // Verify data integrity
    assert_eq!(quote_buffer_account.data.len(), quote_data.len());
    assert_eq!(quote_buffer_account.data, quote_data, "Quote data mismatch");

    println!(
        "Successfully uploaded and verified quote data ({} bytes)",
        quote_data.len()
    );
}
