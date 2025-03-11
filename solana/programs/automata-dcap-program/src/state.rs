use borsh::{BorshSerialize, BorshDeserialize};
use solana_program::pubkey::Pubkey;

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct CounterAccountData {
    count: u64
}

impl CounterAccountData {
    pub fn new() -> Self {
        CounterAccountData {count: 0}
    }

    pub fn increment(&mut self) {
        self.count += 1;
    }

    pub fn current_count(&self) -> u64 {
        self.count
    }
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct OutputAccountData {
    pub close_authority: Pubkey,
    pub verified: bool,
    pub output: Vec<u8>
}