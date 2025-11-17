use anyhow::anyhow;
use zerocopy::little_endian;

pub const INTEL_QE_VENDOR_ID: [u8; 16] = [
    0x93, 0x9A, 0x72, 0x33, 0xF7, 0x9C, 0x4C, 0xA9, 0x94, 0x0A, 0x0D, 0xB3, 0x95, 0x7F, 0x06, 0x07,
];

/// Header of the DCAP Quote data structure.
///
/// We use zerocopy for zero-copy parsing of the quote header from raw bytes.
/// This allows us to safely interpret the raw byte slice as a structured type without copying the data.
/// Benefits:
///
/// 1. Performance: Avoids memory allocation and copying of bytes
/// 2. Safety: Ensures the struct layout is compatible with the raw bytes through compile-time checks
/// 3. Direct memory mapping: Can read directly from memory-mapped files or network buffers
///
/// The FromBytes trait ensures the type is safe to interpret from any byte sequence
/// The FromZeroes trait ensures the type is safe to create from zero bytes
#[derive(Debug, zerocopy::FromBytes, zerocopy::FromZeroes, zerocopy::AsBytes)]
#[repr(C)]
pub struct QuoteHeader {
    /// Version of the quote data structure.
    /// (0)
    pub version: little_endian::U16,

    /// Type of attestation key used by the quoting enclave.
    /// 2 (ECDSA-256-with-P-256 curve)
    /// 3 (ECDSA-384-with-P-384 curve)
    /// (2)
    pub attestation_key_type: little_endian::U16,

    /// TEE for this Attestation
    /// 0x00000000: SGX
    /// 0x00000081: TDX
    /// (4)
    pub tee_type: u32,

    /// Security Version of the Quoting Enclave
    /// (8)
    pub qe_svn: little_endian::U16,

    /// Security Version of the PCE - 0 (Only applicable for SGX Quotes)
    /// (10)
    pub pce_svn: little_endian::U16,

    /// Unique identifier of the QE Vendor.
    /// Value: 939A7233F79C4CA9940A0DB3957F0607 (Intel® SGX QE Vendor)
    /// (12)
    pub qe_vendor_id: [u8; 16],

    /// Custom user-defined data. For the Intel® SGX and TDX DCAP Quote Generation Libraries,
    /// the first 16 bytes contain a Platform Identifier that is used to link a PCK Certificate to an Enc(PPID).
    /// (28)
    pub user_data: [u8; 20],
    // Total size: 48 bytes
}

impl TryFrom<[u8; std::mem::size_of::<QuoteHeader>()]> for QuoteHeader {
    type Error = anyhow::Error;

    fn try_from(value: [u8; std::mem::size_of::<QuoteHeader>()]) -> Result<Self, Self::Error> {
        let quote_header =
            <Self as zerocopy::FromBytes>::read_from(&value).expect("failed to read quote header");

        if quote_header.version.get() < 3 || quote_header.version.get() > 5 {
            return Err(anyhow!(
                "unsupported quote version: {}",
                quote_header.version
            ));
        }

        if quote_header.attestation_key_type.get() != AttestationKeyType::Ecdsa256P256 as u16 {
            return Err(anyhow!("unsupported attestation key type"));
        }

        if quote_header.qe_vendor_id != INTEL_QE_VENDOR_ID {
            return Err(anyhow!("unsupported qe vendor id"));
        }

        Ok(quote_header)
    }
}

/// Attestation Key Type
pub enum AttestationKeyType {
    Ecdsa256P256 = 2,
    Ecdsa384P384 = 3,
}
