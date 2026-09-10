//! DCAP V2 guest; commits canonical schema 2.1 without a legacy wrapper.
#![no_main]
pico_sdk::entrypoint!(main);
pub fn main() {
    let input = pico_sdk::io::read_vec();
    let journal = dcap_rs::v2::verify_guest_input_v2(&input).expect("DCAP V2 verification");
    pico_sdk::io::commit_bytes(&journal);
}
