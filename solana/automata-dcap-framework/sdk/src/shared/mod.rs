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

// https://github.com/risc0/risc0-solana/blob/0af1d39ecde3f9a12d34bc78084a31f1cc6c59ba/solana-verifier/programs/groth_16_verifier/src/lib.rs#L119-L132
// RiscZero Solana Verifier expects that p1_a value to be negated
pub fn negate_g1(point: &[u8; 64]) -> [u8; 64] {
    let modulus_q =
        hex::decode("30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD47").unwrap();

    let mut modulus_arr: [u8; 32] = modulus_q.try_into().unwrap();

    let mut negated_point = [0u8; 64];
    negated_point[..32].copy_from_slice(&point[..32]);

    let mut y = [0u8; 32];
    y.copy_from_slice(&point[32..]);

    subtract_be_bytes(&mut modulus_arr, &y);
    negated_point[32..].copy_from_slice(&modulus_arr);

    negated_point
}

/// Subtract big-endian numbers
fn subtract_be_bytes(a: &mut [u8; 32], b: &[u8; 32]) {
    let mut borrow: u32 = 0;
    for (ai, bi) in a.iter_mut().zip(b.iter()).rev() {
        let result = (*ai as u32).wrapping_sub(*bi as u32).wrapping_sub(borrow);
        *ai = result as u8;
        borrow = (result >> 31) & 1;
    }
}