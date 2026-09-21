//! Minimal-policy DCAP V2 guest. Authentication and compact framing remain mandatory.
//! Mode is fixed in this binary, never selected from untrusted guest input.
#![no_main]
pico_sdk::entrypoint!(main);
pub fn main() {
    let input = pico_sdk::io::read_vec();
    let journal =
        dcap_rs::v2::verify_guest_input_v2_minimal(&input).expect("DCAP V2 minimal verification");
    pico_sdk::io::commit_bytes(&journal);
}
