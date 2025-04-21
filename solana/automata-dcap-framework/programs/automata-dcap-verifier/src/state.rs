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

#[account]
pub struct VerifiedOutput {
    pub owner: Pubkey,
    pub quote_version: u16,
    pub tee_type: u32,
    pub tcb_status: String,
    pub fmspc: [u8; 6],
    pub quote_body: Vec<u8>,
    pub advisor_ids: Option<Vec<String>>,
    pub completed: bool,
}

#[account]
pub struct QeTcbStatus {
    pub status: String,
}

#[account]
pub struct TcbStatus {
    pub sgx_tcb_status: String,
    pub tdx_tcb_status: String,
    pub advisory_ids: Option<Vec<String>>,
}
