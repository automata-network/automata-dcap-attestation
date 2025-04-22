use anchor_lang::prelude::*;

use crate::state::{CertificateAuthority, EnclaveIdentityType, TcbType};


#[event]
pub struct TcbInfoUpdated {
    pub tcb_type: TcbType,
    pub version: u8,
    pub fmspc: [u8; 6],
    pub pda: Pubkey,
}

#[event]
pub struct EnclaveIdentityUpserted {
    pub id: EnclaveIdentityType,
    pub version: u8,
    pub pda: Pubkey,
}


#[event]
pub struct PckCertificateUpserted {
    pub qe_id: [u8; 16],
    pub pce_id: [u8; 2],
    pub tcbm: [u8; 18],
    pub pda: Pubkey,
}


#[event]
pub struct PcsCertificateUpserted {
    pub ca_type: CertificateAuthority,
    pub is_crl: bool,
    pub pda: Pubkey,
}
