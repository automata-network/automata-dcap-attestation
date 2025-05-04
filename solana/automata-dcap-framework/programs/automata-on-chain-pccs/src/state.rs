use anchor_lang::prelude::*;
use crate::types::*;

#[account]
pub struct PckCertificate {
    /// The type of certificate authority that signed this certificate
    pub ca_type: CertificateAuthority,

    /// The ID of the Quality of Execution (QE) that signed this certificate
    pub qe_id: [u8; 16],

    /// The ID of the Platform Configuration Entity (PCE) that signed this certificate
    pub pce_id: [u8; 2],

    /// The TCBM of the certificate
    pub tcbm: [u8; 18],

    /// Certificate data
    pub cert_data: Vec<u8>,

    /// The digest of the certificate
    pub digest: [u8; 32],
}

#[account]
pub struct PcsCertificate {
    /// The type of certificate authority that signed this certificate
    pub ca_type: CertificateAuthority,

    /// Whether this is a CRL
    pub is_crl: bool,

    /// Certificate data
    pub cert_data: Vec<u8>,

    /// The digest of the certificate
    pub digest: [u8; 32],
}

#[account]
pub struct EnclaveIdentity {
    /// The type of enclave identity
    pub identity_type: EnclaveIdentityType,

    /// The version of the enclave identity
    pub version: u8,

    /// The data of the enclave identity
    pub data: Vec<u8>,

    /// The digest of the certificate
    pub digest: [u8; 32],
}

#[account]
pub struct TcbInfo {
    /// The type of TCB
    pub tcb_type: TcbType,

    /// The version of the TCB
    pub version: u8,

    /// The FMSPC of the TCB
    pub fmspc: [u8; 6],

    /// The data of the TCB
    pub data: Vec<u8>,

    /// The digest of the certificate
    pub digest: [u8; 32],
}

#[account]
pub struct DataBuffer {
    pub owner: Pubkey,
    pub total_size: u32,
    pub num_chunks: u8,
    pub complete: bool,
    pub data: Vec<u8>,
    pub signed_digest: [u8; 32]
}