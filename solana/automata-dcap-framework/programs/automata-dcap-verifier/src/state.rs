use anchor_lang::prelude::*;

#[account]
pub struct DataBuffer {
    pub owner: Pubkey,
    pub total_size: u32,
    pub num_chunks: u8,
    pub chunks_received: u8,
    pub complete: bool,
    pub data: Vec<u8>,
}
