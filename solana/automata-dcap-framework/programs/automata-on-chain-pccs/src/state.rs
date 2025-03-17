use anchor_lang::prelude::*;

#[account]
pub struct PckCertificate {
    /// The owner that has permission to modify data in this account.
    pub owner: Pubkey,

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
}


#[account]
pub struct DataBuffer {
    pub owner: Pubkey,
    pub total_size: u32,
    pub num_chunks: u8,
    pub chunks_received: u8,
    pub complete: bool,
    pub data: Vec<u8>,
}

/// Represents the different types of Certificate Authorities in the Intel SGX
/// attestation.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertificateAuthority {
    /// Intel SGX Root CA
    ROOT = 0,

    /// Intel SGX Platform CA
    PLATFORM = 1,

    /// Intel SGX Processor CA
    PROCESSOR = 2,

    /// Intel SGX TCB Signing CA
    SIGNING = 3,
}

impl CertificateAuthority {
    /// Returns the common name associated with this CA type
    pub fn common_name(&self) -> &'static str {
        match self {
            CertificateAuthority::ROOT => "Intel SGX Root CA",
            CertificateAuthority::PLATFORM => "Intel SGX Platform CA",
            CertificateAuthority::PROCESSOR => "Intel SGX Processor CA",
            CertificateAuthority::SIGNING => "Intel SGX TCB Signing CA",
        }
    }

    /// Attempts to convert a u8 to a CertificateAuthority enum.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(CertificateAuthority::ROOT),
            1 => Some(CertificateAuthority::PLATFORM),
            2 => Some(CertificateAuthority::PROCESSOR),
            3 => Some(CertificateAuthority::SIGNING),
            _ => None,
        }
    }
}
