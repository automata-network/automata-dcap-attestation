pub mod ecdsa;
pub mod zk;

use x509_cert::certificate::{Certificate, TbsCertificateInner};
use x509_cert::crl::{CertificateList, TbsCertList};
use der::{Decode, Encode};
use sha2::{Digest, Sha256};

pub fn get_certificate_tbs_and_digest(raw_cert_der: &[u8]) -> ([u8; 32], TbsCertificateInner) {
    let cert = Certificate::from_der(raw_cert_der).unwrap();
    let tbs = cert.tbs_certificate;
    let digest: [u8; 32] = Sha256::digest(tbs.to_der().unwrap().as_slice()).into();
    (digest, tbs)
}

pub fn get_crl_tbs_and_digest(crl_data: &[u8]) -> ([u8; 32], TbsCertList) {
    let crl = CertificateList::from_der(crl_data).unwrap();
    let tbs = crl.tbs_cert_list;
    let digest: [u8; 32] = Sha256::digest(tbs.to_der().unwrap().as_slice()).into();
    (digest, tbs)
}

pub fn get_issuer_common_name(cert: &TbsCertificateInner) -> Option<String> {
    cert.issuer
        .0
        .iter()
        .find(|attr| attr.to_string().starts_with("CN="))
        .map(|attr| {
            let attr_string = attr.to_string();
            attr_string.split("CN=").nth(1).map(|s| s.to_string())
        })
        .flatten()
}