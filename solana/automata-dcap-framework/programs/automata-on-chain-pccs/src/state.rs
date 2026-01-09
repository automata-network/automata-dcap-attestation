use anchor_lang::prelude::*;
use crate::types::*;

// https://docs.rs/x509-cert/latest/src/x509_cert/serial_number.rs.html#37
pub const SERIAL_NUMBER_MAX_LENGTH: usize = 20;

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

    /// The ValidityNotBefore timestamp of the certificate
    pub validity_not_before: i64,

    /// The ValidityNotAfter timestamp of the certificate
    pub validity_not_after: i64,

    /// Serial number of the certificate
    pub serial_number: [u8; SERIAL_NUMBER_MAX_LENGTH],
}

#[account(zero_copy)]
pub struct PcsCertificate {
    /// The digest of the certificate
    pub digest: [u8; 32],

    /// Certificate data
    pub cert_data: [u8; crate::instructions::MAX_CERT_DATA_SIZE],

    /// The ValidityNotBefore timestamp of the certificate
    pub validity_not_before: i64,

    /// The ValidityNotAfter timestamp of the certificate
    /// This field is optional for CRLs
    pub validity_not_after: i64,

    /// Serial number of the certificate
    /// Zero Bytes if this is a CRL
    pub serial_number: [u8; SERIAL_NUMBER_MAX_LENGTH],

    /// The type of certificate authority that signed this certificate
    pub ca_type: u8,

    /// Whether this is a CRL; 0 for certificate, 1 for CRL
    pub is_crl: u8,

    /// The size of the certificate data
    pub cert_data_size: u16,
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

    /// The issuance timestamp of the collateral
    pub issue_timestamp: i64,

    /// The timestamp when the collateral expects to be updated
    pub next_update_timestamp: i64,
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

    /// The issuance timestamp of the collateral
    pub issue_timestamp: i64,

    /// The timestamp when the collateral expects to be updated
    pub next_update_timestamp: i64,
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
