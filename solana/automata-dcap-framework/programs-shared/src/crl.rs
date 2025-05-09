use anyhow::{Result, anyhow};
use sha2::{Digest, Sha256};
use x509_parser::revocation_list::TbsCertList;

pub fn get_crl_tbs_and_digest<'a>(crl_data: &'a [u8]) -> ([u8; 32], TbsCertList<'a>) {
    let crl = x509_parser::parse_x509_crl(crl_data).unwrap().1;
    let tbs = crl.tbs_cert_list;
    let digest: [u8; 32] = Sha256::digest(tbs.as_ref()).into();
    (digest, tbs)
}

pub fn get_crl_validity<'a>(tbs: &'a TbsCertList<'a>) -> (i64, i64) {
    let this_update = tbs.this_update.timestamp();
    let next_update = match tbs.next_update {
        Some(next_update) => next_update.timestamp(),
        None => i64::MAX
    };
    (this_update, next_update)
}

pub fn check_certificate_revocation(serial_number: &[u8], crl_data: &[u8]) -> Result<()> {
    let crl = x509_parser::parse_x509_crl(crl_data).unwrap().1;
    let revoked_certificates = crl.tbs_cert_list.revoked_certificates;

    if !revoked_certificates.is_empty() {
        for revoked in revoked_certificates {
            if serial_number == revoked.raw_serial() {
                return Err(anyhow!("Certificate is revoked"));
            }
        }
    }

    Ok(())
}
