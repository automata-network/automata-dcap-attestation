pub mod entrypoint;
pub mod instruction;
pub mod state;
pub mod processor;
pub mod error;

pub const DCAP_COUNTER_ADDR: &str = "DcapH8Bt1y6MQHE1hR2Rp1WEBeWfog2Kh9UxtG8UMaNu";
pub const RISC0_GROTH16_VERIFIER_ADDR: &str = "5HrF6mJAaSFdAym2xZixowzVifPyyzTuTs3viYKdjy4s";
pub const SP1_DCAP_GROTH16_VERIFIER_ADDR: &str = "2LUaFQTJ7F96A5x1z5sXfbDPM2asGnrQ2hsE6zVDMhXZ";

#[cfg(test)]
mod tests;