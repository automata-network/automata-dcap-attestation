use super::{Input, InputType};
use borsh::BorshSerialize;

pub fn serialize_input(
    input_type: InputType,
    subject_data: Vec<u8>,
    issuer_raw_der: Vec<u8>,
) -> Vec<u8> {
    let input = Input {
        input_type,
        subject_data,
        issuer_raw_der,
    };

    let mut input_bytes = vec![];
    input.serialize(&mut input_bytes).expect(
        "Failed to serialize input"
    );

    input_bytes
}