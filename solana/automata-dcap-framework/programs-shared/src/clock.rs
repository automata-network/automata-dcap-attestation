use der::Decode;
use x509_cert::{Certificate, crl::CertificateList};
use x509_cert::time::Time;

/// Get the validity period of a given X.509 certificate.
pub fn get_certificate_validity(cert_data: &[u8]) -> (i64, i64) {
    let cert = Certificate::from_der(cert_data).unwrap();
    
    let validity = &cert.tbs_certificate.validity;
    
    // Convert the ASN.1 time to Unix timestamp
    let not_before = der_time_to_unix_timestamp(&validity.not_before);
    let not_after = der_time_to_unix_timestamp(&validity.not_after);

    (not_before, not_after)
}

/// Get the validity period of a given CRL.
pub fn get_crl_validity(crl: &[u8]) -> (i64, i64) {
    let crl = CertificateList::from_der(crl).unwrap();
    
    // Convert the ASN.1 time to Unix timestamp
    let this_update = der_time_to_unix_timestamp(&crl.tbs_cert_list.this_update);

    let next_update = if let Some(next_update) = &crl.tbs_cert_list.next_update {
        der_time_to_unix_timestamp(next_update)
    } else {
        // If nextUpdate is not present, we assume it is valid indefinitely
        i64::MAX
    };

    (this_update, next_update)
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
