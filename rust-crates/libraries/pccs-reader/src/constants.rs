// TEE Type
pub const SGX_TEE_TYPE: u32 = 0x00000000;
pub const TDX_TEE_TYPE: u32 = 0x00000081;

// Certificate Authority Names
pub const INTEL_ROOT_CA_CN: &str = "Intel SGX Root CA";
pub const INTEL_TCB_SIGNING_CA_CN: &str = "Intel SGX TCB Signing";
pub const INTEL_PCK_PLATFORM_CA_CN: &str = "Intel SGX PCK Platform CA";
pub const INTEL_PCK_PROCESSOR_CA_CN: &str = "Intel SGX PCK Processor CA";
