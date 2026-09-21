//! DCAP V2 guest; commits canonical schema 2.1 without a legacy wrapper.
#![no_main]
use risc0_zkvm::guest::env;
use std::io::Read;
risc0_zkvm::guest::entry!(main);
fn main() {
    let mut input = Vec::new();
    env::stdin().read_to_end(&mut input).expect("guest input");
    let journal = dcap_rs::v2::verify_guest_input_v2(&input).expect("DCAP V2 verification");
    env::commit_slice(&journal);
}
