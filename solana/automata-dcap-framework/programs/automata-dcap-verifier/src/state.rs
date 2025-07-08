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
    pub fmspc: [u8; 6],
    pub quote_body: Vec<u8>,
    pub integrity_verified: bool,
    pub isv_signature_verified: bool,
    pub pck_leaf_verified: bool,
    pub pck_intermediate_verified: bool,
    pub pck_root_verified: bool,
    pub fmspc_tcb_status: u8,
    pub tdx_module_tcb_status: u8,
    pub qe_tcb_status: u8,
    pub advisory_ids: Option<Vec<String>>,
}
