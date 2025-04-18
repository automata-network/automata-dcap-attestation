pub mod ecdsa;
pub mod pck;

use x509_cert::certificate::TbsCertificateInner;

pub fn get_num_chunks(data_len: usize, chunk_size: usize) -> u8 {
    ((data_len as f64 / chunk_size as f64).ceil()) as u8
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