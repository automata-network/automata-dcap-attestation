use sha2::{Digest, Sha256};

use x509_parser::certificate::TbsCertificate;

pub fn get_certificate_tbs_and_digest<'a>(
    raw_cert_der: &'a [u8],
) -> ([u8; 32], TbsCertificate<'a>) {
    let cert = x509_parser::parse_x509_certificate(raw_cert_der).unwrap().1;
    let tbs = cert.tbs_certificate;
    let digest: [u8; 32] = Sha256::digest(tbs.as_ref()).into();
    (digest, tbs)
}

pub fn get_certificate_validity<'a>(tbs: &'a TbsCertificate<'a>) -> (i64, i64) {
    let not_before = tbs.validity().not_before.timestamp();
    let not_after = tbs.validity().not_after.timestamp();
    (not_before, not_after)
}

pub fn get_certificate_serial<'a>(tbs: &'a TbsCertificate<'a>) -> [u8; 20] {
    let mut result = [0u8; 20];

    let serial_number_raw = tbs.raw_serial();
    let len = serial_number_raw.len();

    if len > 20 {
        // we may receive a serial number that is 21 bytes long
        // this is ok if and only if the first byte is 0
        assert!(
            serial_number_raw[0] == 0,
            "Serial number must be 20 bytes or less"
        );
    }

    result.copy_from_slice(&serial_number_raw[len - 20..]);

    result
}

// https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/39989a42bbbb0c968153a47254b6de79a27eb603/QuoteVerification/QvE/Enclave/qve.cpp#L92-L100
pub const INTEL_ROOT_PUB_KEY: [u8; 65] = [
    0x04, 0x0b, 0xa9, 0xc4, 0xc0, 0xc0, 0xc8, 0x61, 0x93, 0xa3, 0xfe, 0x23, 0xd6, 0xb0, 0x2c, 0xda,
    0x10, 0xa8, 0xbb, 0xd4, 0xe8, 0x8e, 0x48, 0xb4, 0x45, 0x85, 0x61, 0xa3, 0x6e, 0x70, 0x55, 0x25,
    0xf5, 0x67, 0x91, 0x8e, 0x2e, 0xdc, 0x88, 0xe4, 0x0d, 0x86, 0x0b, 0xd0, 0xcc, 0x4e, 0xe2, 0x6a,
    0xac, 0xc9, 0x88, 0xe5, 0x05, 0xa9, 0x53, 0x55, 0x8c, 0x45, 0x3f, 0x6b, 0x09, 0x04, 0xae, 0x73,
    0x94,
];
