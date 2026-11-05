//! Minimal-policy DCAP V2 guest. Authentication and compact framing remain mandatory.
//! Mode is fixed in this binary, never selected from untrusted guest input.
#![no_main]
risc0_zkvm::guest::entry!(main);
pub fn main() {
    let mut input = Vec::new();
    std::io::Read::read_to_end(&mut risc0_zkvm::guest::env::stdin(), &mut input)
        .expect("guest input");
    let journal =
        dcap_rs::v2::verify_guest_input_v2_minimal(&input).expect("DCAP V2 minimal verification");
    risc0_zkvm::guest::env::commit_slice(&journal);
}
