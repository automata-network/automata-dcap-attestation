use anyhow::{Result, anyhow};
use der::{Decode, Encode};
use sha2::{Digest, Sha256};
use x509_cert::{
    crl::{CertificateList, TbsCertList},
    serial_number::SerialNumber,
};

pub fn get_crl_tbs_and_digest(crl_data: &[u8]) -> ([u8; 32], TbsCertList) {
    let crl = CertificateList::from_der(crl_data).unwrap();
    let tbs = crl.tbs_cert_list;
    let digest: [u8; 32] = Sha256::digest(tbs.to_der().unwrap().as_slice()).into();
    (digest, tbs)
}

pub fn check_certificate_revocation(serial_number: &[u8], crl_data: &[u8]) -> Result<()> {
    let crl = CertificateList::from_der(&crl_data).unwrap();

    if let Some(revoked_list) = crl.tbs_cert_list.revoked_certificates {
        for revoked_cert in revoked_list {
            let revoked_serial_number_bytes = revoked_cert.serial_number.as_bytes();
            if revoked_serial_number_bytes == serial_number {
                return Err(anyhow!("Certificate has been revoked: {:?}", serial_number));
            }
        }
    }

    Ok(())
}

pub fn convert_serial_number_to_raw(serial_number: &SerialNumber) -> [u8; 20] {
    let mut result = [0u8; 20];
    let bytes = serial_number.as_bytes();

    let len = bytes.len();

    if len > 20 {
        // we may receive a serial number that is 21 bytes long
        // this is ok if and only if the first byte is 0
        assert!(bytes[0] == 0, "Serial number must be 20 bytes or less");
    }

    result.copy_from_slice(&bytes[len - 20..]);

    result
}
