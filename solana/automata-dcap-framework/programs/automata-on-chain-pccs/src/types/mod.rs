use anchor_lang::prelude::*;
use std::{
    str::FromStr,
    result::Result
};

/// Represents the different types of Certificate Authorities in the Intel SGX
/// attestation.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
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

impl FromStr for CertificateAuthority {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Intel SGX Root CA" => Ok(CertificateAuthority::ROOT),
            "Intel SGX PCK Platform CA" => Ok(CertificateAuthority::PLATFORM),
            "Intel SGX PCK Processor CA" => Ok(CertificateAuthority::PROCESSOR),
            "Intel SGX TCB Signing" => Ok(CertificateAuthority::SIGNING),
            _ => Err(String::from("Unknown Issuer CA")),
        }
    }
}

impl CertificateAuthority {
    /// Returns the common name associated with this CA type
    pub fn common_name(&self) -> &'static str {
        match self {
            CertificateAuthority::ROOT => "Intel SGX Root CA",
            CertificateAuthority::PLATFORM => "Intel SGX PCK Platform CA",
            CertificateAuthority::PROCESSOR => "Intel SGX PCK Processor CA",
            CertificateAuthority::SIGNING => "Intel SGX TCB Signing",
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

    /// Returns the issuer of the certificate or CRL based on the CA type.
    pub fn get_issuer(&self, is_crl: bool) -> Self {
        if is_crl && *self != CertificateAuthority::SIGNING {
            self.clone()
        } else {
            CertificateAuthority::ROOT
        }
    }
}

/// Represents the different types of Enclave Identities in the Intel SGX
/// attestation.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnclaveIdentityType {
    QE = 0,
    QVE = 1,
    TdQe = 2,
}

impl EnclaveIdentityType {
    pub fn common_name(&self) -> &'static str {
        match self {
            EnclaveIdentityType::QE => "QE",
            EnclaveIdentityType::QVE => "QVE",
            EnclaveIdentityType::TdQe => "TD_QE",
        }
    }

    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(EnclaveIdentityType::QE),
            1 => Some(EnclaveIdentityType::QVE),
            2 => Some(EnclaveIdentityType::TdQe),
            _ => None,
        }
    }
}

/// Represents different types of TCB
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcbType {
    Sgx = 0,
    Tdx = 1,
}

impl TcbType {
    pub fn common_name(&self) -> &'static str {
        match self {
            TcbType::Sgx => "SGX",
            TcbType::Tdx => "TDX",
        }
    }

    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(TcbType::Sgx),
            1 => Some(TcbType::Tdx),
            _ => None,
        }
    }
}
