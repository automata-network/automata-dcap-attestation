pub mod certs;
pub mod clock;
pub mod crl;

use x509_cert::name::RdnSequence;

pub fn get_cn_from_rdn_sequence(rdn_seq: &RdnSequence) -> Option<String> {
    rdn_seq
        .0
        .iter()
        .find(|attr| attr.to_string().starts_with("CN="))
        .map(|attr| {
            let attr_string = attr.to_string();
            attr_string.split("CN=").nth(1).map(|s| s.to_string())
        })
        .flatten()
}