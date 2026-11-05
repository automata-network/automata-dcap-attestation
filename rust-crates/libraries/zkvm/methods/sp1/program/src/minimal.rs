//! Minimal-policy DCAP V2 guest. Authentication and compact framing remain mandatory.
//! Mode is fixed in this binary, never selected from untrusted guest input.
#![no_main]
sp1_zkvm::entrypoint!(main);
pub fn main() {
    let input = sp1_zkvm::io::read_vec();
    let journal =
        dcap_rs::v2::verify_guest_input_v2_minimal(&input).expect("DCAP V2 minimal verification");
    sp1_zkvm::io::commit_slice(&journal);
}
