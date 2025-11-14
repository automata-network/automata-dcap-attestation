use zerocopy::little_endian;

// sgx_report.h in linux-sgx repository by Intel.
const SGX_CPUSVN_SIZE: usize = 16;
const SGX_HASH_SIZE: usize = 32;

#[derive(Debug, zerocopy::FromBytes, zerocopy::FromZeroes, zerocopy::AsBytes)]
#[repr(C)]
pub struct EnclaveReportBody {
    // (0) CPU Security Version
    // uint8_t cpusvn[SGX_CPUSVN_SIZE];
    cpusvn: [u8; SGX_CPUSVN_SIZE],

    // (16) Selector for which fields are defined in SSA.MISC
    // uint32_t misc_select;
    pub misc_select: little_endian::U32,

    // (20) Reserved1 for future use
    // uint8_t reserved1[12];
    _reserved_1: [u8; 12],

    // (32) Enclave extended product ID
    // uint8_t isvextprodid[16];
    _isv_ext_prod_id: [u8; 16],

    // (48) Enclave attributes
    // sgx_attributes_t attributes;
    pub sgx_attributes: [u8; 16],

    // (64) Enclave measurement
    // uint8_t mrenclave[SGX_HASH_SIZE];
    pub mr_enclave: [u8; SGX_HASH_SIZE],

    // (96) Reserved2 for future use
    // uint8_t reserved2[32];
    _reserved_2: [u8; 32],

    // (128) The value of the enclave's SIGNER measurement
    // uint8_t mrsigner[SGX_HASH_SIZE];
    pub mr_signer: [u8; SGX_HASH_SIZE],

    // (160) Reserved3 for future use
    // uint8_t reserved3[32];
    _reserved_3: [u8; 32],

    // (192) Enclave Configuration Security Version
    // uint8_t configid[64];
    _config_id: [u8; 64],

    // (256) Enclave product ID
    // uint16_t isvprodid;
    pub isv_prod_id: little_endian::U16,

    // (258) Enclave security version
    // uint16_t isvsvn;
    pub isv_svn: little_endian::U16,

    // (260) Enclave configuration security version
    // uint16_t configsvn;
    _config_svn: little_endian::U16,

    // (262) Reserved4 for future use
    // uint8_t reserved4[42];
    _reserved_4: [u8; 42],

    // (304) Enclave family ID
    // uint8_t isv_family_id[16];
    _isv_family_id: [u8; 16],

    // (320) User Report data
    // sgx_report_data_t report_data;
    pub user_report_data: [u8; 64],
    // Total 384 bytes
}

impl TryFrom<[u8; std::mem::size_of::<EnclaveReportBody>()]> for EnclaveReportBody {
    type Error = anyhow::Error;

    fn try_from(
        value: [u8; std::mem::size_of::<EnclaveReportBody>()],
    ) -> Result<Self, Self::Error> {
        let report = <Self as zerocopy::FromBytes>::read_from(&value)
            .expect("failed to read enclave report body");

        Ok(report)
    }
}

#[derive(Debug, zerocopy::FromBytes, zerocopy::FromZeroes, zerocopy::AsBytes)]
#[repr(C)]
pub struct Td10ReportBody {
    // (0) Describes the TCB of TDX.
    // uint8_t tee_tcb_svn[16];
    pub tee_tcb_svn: [u8; 16],

    // (16) Measurement of the TDX Module.
    // uint8_t mrseam[48];
    pub mr_seam: [u8; 48],

    // (64) Measurement of the TDX Module Signer.
    // uint8_t mrsignerseam[48];
    pub mr_signer_seam: [u8; 48],

    // (112) TDX Attributes.
    // uint8_t seam_attributes[8];
    pub seam_attributes: [u8; 8],

    // (120) TD Attributes.
    // uint8_t td_attributes[8];
    pub td_attributes: [u8; 8],

    // (128) XFAM (eXtended Features Available Mask) is defined as a 64b bitmap,
    // which has the same format as XCR0 or IA32_XSS MSR.
    // uint8_t xfam[8§];
    pub xfam: [u8; 8],

    // (136) Measurement of the initial contents of the TD.
    // uint8_t mrtd[48];
    pub mr_td: [u8; 48],

    // (184) Software-defined ID for non-owner-defined configuration of the TD,
    // e.g., runtime or OS configuration.
    // uint8_t mrconfigid[48];
    pub mr_config_id: [u8; 48],

    // (232) Software-defined ID for the TD’s owner.
    // uint8_t mrowner[48];
    pub mr_owner: [u8; 48],

    // (280) Software-defined ID for owner-defined configuration of the TD,
    // e.g., specific to the workload rather than the runtime or OS.
    // uint8_t mrownerconfig[48];
    pub mr_owner_config: [u8; 48],

    // (328) Measurement of the Root of Trust for Measurement (RTM) for the TD.
    // uint8_t rtmr0[48];
    pub rtm_r0: [u8; 48],

    // (376) Measurement of the Root of Trust for Measurement (RTM) for the TD.
    // uint8_t rtmr1[48];
    pub rtm_r1: [u8; 48],

    // (424) Measurement of the Root of Trust for Measurement (RTM) for the TD.
    // uint8_t rtmr2[48];
    pub rtm_r2: [u8; 48],

    // (472) Measurement of the Root of Trust for Measurement (RTM) for the TD.
    // uint8_t rtmr3[48];
    pub rtm_r3: [u8; 48],

    // (520) User Report Data.
    // sgx_report_data_t report_data;
    pub user_report_data: [u8; 64],
    // Total 584 bytes
}

impl TryFrom<[u8; std::mem::size_of::<Td10ReportBody>()]> for Td10ReportBody {
    type Error = anyhow::Error;

    fn try_from(value: [u8; std::mem::size_of::<Td10ReportBody>()]) -> Result<Self, Self::Error> {
        let report = <Self as zerocopy::FromBytes>::read_from(&value)
            .expect("failed to read tdx report body");

        Ok(report)
    }
}

#[derive(Debug, zerocopy::FromBytes, zerocopy::FromZeroes, zerocopy::AsBytes)]
#[repr(C)]
pub struct Td15ReportBody {
    pub td_report: Td10ReportBody,

    /// (584) Describes the current TCB of TDX. This value may will be different than TEE_TCB_SVN by
    /// loading a new version of the TDX Module using the TD Preserving update capability)
    pub tee_tcb_svn2: [u8; 16],

    /// (600) Measurement of the initial contents of the Migration TD
    pub mr_service_td: [u8; 48], // Total 648 bytes
}

impl TryFrom<[u8; std::mem::size_of::<Td15ReportBody>()]> for Td15ReportBody {
    type Error = anyhow::Error;

    fn try_from(value: [u8; std::mem::size_of::<Td15ReportBody>()]) -> Result<Self, Self::Error> {
        let report = <Self as zerocopy::FromBytes>::read_from(&value)
            .expect("failed to read tdx report body");

        Ok(report)
    }
}
