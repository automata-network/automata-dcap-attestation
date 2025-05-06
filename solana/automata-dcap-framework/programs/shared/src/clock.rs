use der::Decode;
use x509_cert::{Certificate, crl::CertificateList};
use x509_cert::time::Time;

/// Checks if the current timestamp falls within the validity range of a given X.509 certificate.
/// Returns true if valid, false if not valid.
pub fn is_certificate_valid(cert_data: &[u8], current_timestamp: i64) -> bool {
    let cert = Certificate::from_der(cert_data).unwrap();
    
    let validity = &cert.tbs_certificate.validity;
    
    // Convert the ASN.1 time to Unix timestamp
    let not_before = der_time_to_unix_timestamp(&validity.not_before);
    let not_after = der_time_to_unix_timestamp(&validity.not_after);

    current_timestamp >= not_before && current_timestamp <= not_after
}

/// Checks if the current timestamp falls within the validity range of a given X.509 CRL.
/// Returns true if valid, false if not valid.
pub fn is_crl_valid(crl: &[u8], current_timestamp: i64) -> bool {
    let crl = CertificateList::from_der(crl).unwrap();
    
    // Convert the ASN.1 time to Unix timestamp
    let this_update = der_time_to_unix_timestamp(&crl.tbs_cert_list.this_update);

    current_timestamp >= this_update
}

/// Checks if a JSON collateral (EnclaveIdentity or TcbInfo) with explicit validity dates is valid.
/// Returns true if valid, false if not valid.
pub fn is_collateral_valid(issue_timestamp: i64, next_update: i64, current_timestamp: i64) -> bool {
    current_timestamp >= issue_timestamp && current_timestamp <= next_update
}

/// Helper function to convert ASN.1 Time to Unix timestamp.
fn der_time_to_unix_timestamp(time: &Time) -> i64 {
    // Implementation will depend on the x509_cert library's Time type
    match time {
        Time::UtcTime(t) => {
            t.to_unix_duration().as_secs().try_into().unwrap()
        },
        Time::GeneralTime(t) => {
            t.to_unix_duration().as_secs().try_into().unwrap()
        }
    }
}
