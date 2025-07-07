pub mod certs;
pub mod crl;
pub mod zk;

pub use x509_parser;

use x509_parser::x509::X509Name;

pub fn get_cn_from_x509_name<'a>(name: &'a X509Name<'_>) -> Option<&'a str> {
    name.iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
}