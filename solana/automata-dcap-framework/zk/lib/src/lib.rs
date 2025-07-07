use borsh::{BorshDeserialize, BorshSerialize};

#[derive(BorshDeserialize, BorshSerialize, PartialEq)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum InputType {
    X509 = 0,
    CRL = 1,
    TcbInfo = 2,
    Identity = 3,
}

#[derive(BorshDeserialize, BorshSerialize)]
pub struct Input {
    pub input_type: InputType,
    pub subject_data: Vec<u8>,
    pub issuer_raw_der: Vec<u8>,
}