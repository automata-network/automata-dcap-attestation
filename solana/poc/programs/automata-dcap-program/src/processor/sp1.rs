use borsh::{BorshDeserialize, BorshSerialize};

#[derive(BorshDeserialize, BorshSerialize)]
pub struct SP1Groth16Proof {
    pub proof: Vec<u8>,
    /// SHA256 of the public inputs
    pub sp1_public_inputs_hash: Vec<u8>,
}