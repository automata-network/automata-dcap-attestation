//! SP1 zkVM guest program for DCAP attestation verification.
//!
//! This program runs inside the SP1 zkVM and verifies Intel SGX/TDX quotes.

#![no_main]
sp1_zkvm::entrypoint!(main);

use std::time::{Duration, SystemTime};
use tiny_keccak::{Hasher, Keccak};

use automata_dcap_zkvm::GuestInput;
use dcap_rs::{
    types::{collateral::Collateral, quote::Quote},
    verify_dcap_quote,
};

pub fn main() {
    // Read the input bytes from the host
    let input_bytes: Vec<u8> = sp1_zkvm::io::read_vec();

    // Decode the input
    let input = GuestInput::sol_abi_decode(&input_bytes);
    let quote = Quote::read(&mut input.raw_quote.as_slice()).unwrap();
    let current_time = SystemTime::UNIX_EPOCH + Duration::from_secs(input.timestamp);

    let collaterals = &input.collateral;

    // Pre-process the output hashes
    let tcb_content_hash = collaterals
        .tcb_info
        .get_tcb_info()
        .unwrap()
        .get_content_hash()
        .unwrap();
    let qeidentity_content_hash = collaterals
        .qe_identity
        .get_enclave_identity()
        .unwrap()
        .get_content_hash()
        .unwrap();
    let sgx_intel_root_ca_cert_hash = Collateral::get_cert_hash(
        &collaterals.tcb_info_and_qe_identity_issuer_chain[1], // SGX Intel Root CA
    )
    .unwrap();
    let sgx_tcb_signing_cert_hash = Collateral::get_cert_hash(
        &collaterals.tcb_info_and_qe_identity_issuer_chain[0], // Intel TCB Signing Cert
    )
    .unwrap();
    let sgx_intel_root_ca_crl_hash = Collateral::get_crl_hash(&collaterals.root_ca_crl).unwrap();
    let sgx_pck_crl_hash = Collateral::get_crl_hash(&collaterals.pck_crl).unwrap();

    // Verify the quote
    let output = verify_dcap_quote(current_time, input.collateral, quote).unwrap();

    let serial_output = output.to_vec();

    // Get the hash of the quote
    let mut keccak = Keccak::v256();
    keccak.update(input.raw_quote.as_slice());
    let mut hash = [0u8; 32];
    keccak.finalize(&mut hash);

    // Build the journal output
    // Format:
    // - serial_output_len (2 bytes BE)
    // - serial_output (VerifiedOutput)
    // - current_time (8 bytes BE)
    // - tcbinfo_content_hash
    // - qeidentity_content_hash
    // - sgx_intel_root_ca_cert_hash
    // - sgx_tcb_signing_cert_hash
    // - sgx_intel_root_ca_crl_hash
    // - sgx_pck_crl_hash
    // - quote_hash
    let mut program_output: Vec<u8> = vec![];
    let output_len: u16 = serial_output.len() as u16;

    program_output.extend_from_slice(&output_len.to_be_bytes());
    program_output.extend_from_slice(&serial_output);
    program_output.extend_from_slice(&input.timestamp.to_be_bytes());
    program_output.extend_from_slice(&tcb_content_hash);
    program_output.extend_from_slice(&qeidentity_content_hash);
    program_output.extend_from_slice(&sgx_intel_root_ca_cert_hash);
    program_output.extend_from_slice(&sgx_tcb_signing_cert_hash);
    program_output.extend_from_slice(&sgx_intel_root_ca_crl_hash);
    program_output.extend_from_slice(&sgx_pck_crl_hash);
    program_output.extend_from_slice(&hash);

    // Commit the output to the public values
    sp1_zkvm::io::commit_slice(&program_output);
}
