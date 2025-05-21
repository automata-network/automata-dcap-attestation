use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
#[repr(u8)]
pub enum CertificateAuthority {
    ROOT,
    PROCESSOR,
    PLATFORM,
    SIGNING,
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
    pub fn common_name(&self) -> &'static str {
        match self {
            CertificateAuthority::ROOT => "Intel SGX Root CA",
            CertificateAuthority::PLATFORM => "Intel SGX PCK Platform CA",
            CertificateAuthority::PROCESSOR => "Intel SGX PCK Processor CA",
            CertificateAuthority::SIGNING => "Intel SGX TCB Signing",
        }
    }

    pub fn get_issuer(&self, is_crl: bool) -> Self {
        if is_crl && *self != CertificateAuthority::SIGNING {
            self.clone()
        } else {
            CertificateAuthority::ROOT
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
#[repr(u8)]
pub enum EnclaveIdentityType {
    QE,
    QVE,
    TdQe,
}

impl EnclaveIdentityType {
    pub fn common_name(&self) -> String {
        match self {
            EnclaveIdentityType::TdQe => "TD_QE".to_string(),
            EnclaveIdentityType::QE => "QE".to_string(),
            EnclaveIdentityType::QVE => "QVE".to_string(),
        }
    }
}


#[derive(Debug, Clone, PartialEq, Eq, Copy)]
#[repr(u8)]
pub enum TcbType {
    Sgx,
    Tdx,
}

impl TcbType {
    pub fn common_name(&self) -> String {
        match self {
            TcbType::Sgx => "SGX".to_string(),
            TcbType::Tdx => "TDX".to_string(),
        }
    }
}

impl FromStr for TcbType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "SGX" => Ok(TcbType::Sgx),
            "TDX" => Ok(TcbType::Tdx),
            _ => Err(String::from("Unknown TCB Type")),
        }
    }
}
