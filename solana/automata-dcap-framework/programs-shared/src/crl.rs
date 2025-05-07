use der::{Decode, Encode};
use sha2::{Digest, Sha256};
use x509_cert::{
    Certificate,
    crl::{CertificateList, TbsCertList},
};
use anyhow::{Result, anyhow};

pub fn get_crl_tbs_and_digest(crl_data: &[u8]) -> ([u8; 32], TbsCertList) {
    let crl = CertificateList::from_der(crl_data).unwrap();
    let tbs = crl.tbs_cert_list;
    let digest: [u8; 32] = Sha256::digest(tbs.to_der().unwrap().as_slice()).into();
    (digest, tbs)
}

pub fn check_certificate_revocation(certificate_data: &[u8], crl_data: &[u8]) -> Result<()> {
    let certificate = Certificate::from_der(&certificate_data).unwrap();
    let crl = CertificateList::from_der(&crl_data).unwrap();

    if let Some(revoked_list) = crl.tbs_cert_list.revoked_certificates {
        for revoked_cert in revoked_list {
            if revoked_cert.serial_number == certificate.tbs_certificate.serial_number {
                return Err(anyhow!("Certificate has been revoked"));
            }
        }
    }

    Ok(())
}
