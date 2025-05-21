use anchor_lang::prelude::*;

// https://docs.rs/x509-cert/latest/src/x509_cert/serial_number.rs.html#37
pub const SERIAL_NUMBER_MAX_LENGTH: usize = 20;

/// Most collaterals are well below this size
/// CPI Instructions are limited to 10KB account space expansion, so this is a safe limit
pub const MAX_COLLATERAL_SIZE: usize = 9216;

#[account(zero_copy)]
pub struct PckCertificate {
    /// The digest of the certificate
    pub digest: [u8; 32],

    /// Certificate data
    pub cert_data: [u8; MAX_COLLATERAL_SIZE],

    /// The ValidtyNotBefore timestamp of the certificate
    pub validity_not_before: i64,

    /// The ValidtyNotAfter timestamp of the certificate
    pub validity_not_after: i64,

    /// Serial number of the certificate
    pub serial_number: [u8; SERIAL_NUMBER_MAX_LENGTH],

    /// The ID of the Quality of Execution (QE) that signed this certificate
    pub qe_id: [u8; 16],

    /// The ID of the Platform Configuration Entity (PCE) that signed this certificate
    pub pce_id: [u8; 2],

    /// The TCBM of the certificate
    pub tcbm: [u8; 18],
}

#[account(zero_copy)]
pub struct PcsCertificate {
    /// The digest of the certificate
    pub digest: [u8; 32],

    /// Certificate data
    pub cert_data: [u8; MAX_COLLATERAL_SIZE],

    /// The ValidtyNotBefore timestamp of the certificate
    pub validity_not_before: i64,

    /// The ValidtyNotAfter timestamp of the certificate
    /// This field is optional for CRLs
    pub validity_not_after: i64,

    /// Serial number of the certificate
    /// Zero Bytes if this is a CRL
    pub serial_number: [u8; SERIAL_NUMBER_MAX_LENGTH],

    /// The type of certificate authority that signed this certificate
    pub ca_type: u8,

    /// Whether this is a CRL; 0 for certificate, 1 for CRL
    pub is_crl: u8,

    /// Padding to align the struct to 8 bytes
    _padding: [u8; 2],
}

#[account(zero_copy)]
pub struct EnclaveIdentity {
    /// The digest of the certificate
    pub digest: [u8; 32],

    /// The data of the enclave identity
    pub data: [u8; MAX_COLLATERAL_SIZE],

    /// The issuance timestamp of the collateral
    pub issue_timestamp: i64,

    /// The timestamp when the collateral expects to be updated
    pub next_update_timestamp: i64,

    /// The version of the enclave identity
    pub version: u32,

    /// The type of enclave identity
    pub identity_type: u8,

    /// padding to align the struct to 8 bytes
    _padding: [u8; 3]
}

#[account(zero_copy)]
pub struct TcbInfo {
    /// The digest of the certificate
    pub digest: [u8; 32],

    /// The data of the TCB
    pub data: [u8; MAX_COLLATERAL_SIZE],

    /// The issuance timestamp of the collateral
    pub issue_timestamp: i64,

    /// The timestamp when the collateral expects to be updated
    pub next_update_timestamp: i64,

    /// The version of the TCB
    pub version: u32,

    /// The FMSPC of the TCB
    pub fmspc: [u8; 6],

    /// The type of TCB
    pub tcb_type: u8,

    /// padding to align the struct to 8 bytes
    _padding: [u8; 5]
}

#[account]
pub struct DataBuffer {
    pub owner: Pubkey,
    pub signed_digest: [u8; 32],
    pub data: [u8; MAX_COLLATERAL_SIZE],
    pub total_size: u32,
    pub num_chunks: u8,
    pub complete: bool,
}