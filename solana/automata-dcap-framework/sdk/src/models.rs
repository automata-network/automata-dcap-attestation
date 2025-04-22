
#[derive(Debug, Clone, PartialEq, Eq, Copy)]
#[repr(u8)]
pub enum CertificateAuthority {
    ROOT,
    PLATFORM,
    PROCESSOR,
    SIGNING,
}

impl CertificateAuthority {
    pub fn common_name(&self) -> String {
        match self {
            CertificateAuthority::ROOT => "Intel SGX Root CA".to_string(),
            CertificateAuthority::PLATFORM => "Intel SGX Platform CA".to_string(),
            CertificateAuthority::PROCESSOR => "Intel SGX Processor CA".to_string(),
            CertificateAuthority::SIGNING => "Intel SGX TCB Signing CA".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
#[repr(u8)]
pub enum EnclaveIdentityType {
    TdQe,
    QE,
    QVE,
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
