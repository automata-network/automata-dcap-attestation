//! DCAP V2 guest; commits canonical schema 2.1 without a legacy wrapper.
#![no_main]
sp1_zkvm::entrypoint!(main);
pub fn main() {
    let input = sp1_zkvm::io::read_vec();
    let journal = dcap_rs::v2::verify_guest_input_v2(&input).expect("DCAP V2 verification");
    sp1_zkvm::io::commit_slice(&journal);
}
