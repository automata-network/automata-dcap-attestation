use anchor_lang::prelude::*;

#[account]
pub struct DataBuffer {
    pub owner: Pubkey,
    pub total_size: u32,
    pub complete: bool,
    pub data: Vec<u8>,
}

#[account]
pub struct VerifiedOutput {
    pub quote_version: u16,
    pub tee_type: u32,
    pub tcb_status: String,
    pub fmspc: [u8; 6],
    pub quote_body: Vec<u8>,
    pub advisor_ids: Option<Vec<String>>,
    pub integrity_verified: bool,
    pub isv_signature_verified: bool,
    pub enclave_source_verified: bool,
    pub tcb_check_verified: bool,
    pub pck_cert_chain_verified: bool,
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
