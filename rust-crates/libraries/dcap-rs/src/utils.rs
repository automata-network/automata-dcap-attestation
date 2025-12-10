use std::time::SystemTime;
use x509_cert::{certificate::CertificateInner, crl::CertificateList};

pub mod keccak {
    use tiny_keccak::{Hasher, Keccak};

    pub fn hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Keccak::v256();
        let mut output = [0u8; 32];
        hasher.update(data);
        hasher.finalize(&mut output);
        output
    }
}

/// A module for serializing and deserializing certificate chains.
pub mod cert_chain {
    use serde::{Deserialize, de, ser};
    use x509_cert::{certificate::CertificateInner, der::EncodePem};

    use super::cert_chain_processor;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<CertificateInner>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = <String>::deserialize(deserializer)?;
        let pem = Box::new(s.as_bytes());
        cert_chain_processor::load_pem_chain_bpf_friendly(&pem).map_err(de::Error::custom)
    }

    pub fn serialize<S>(certs: &Vec<CertificateInner>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut string = String::new();
        for cert in certs {
            string.push_str(
                &cert
                    .to_pem(p256::pkcs8::LineEnding::LF)
                    .map_err(ser::Error::custom)?,
            );
        }
        serializer.serialize_str(&string)
    }
}

/// A module for serializing and deserializing CRLs.
pub mod crl {
    use std::str::FromStr;

    use pem::Pem;
    use serde::{Deserialize, Deserializer, Serializer, de, ser};
    use x509_cert::crl::CertificateList;
    use x509_cert::der::{Decode, Encode};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<CertificateList, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = <String>::deserialize(deserializer)?;
        let pem = Pem::from_str(&s).map_err(de::Error::custom)?;
        CertificateList::from_der(pem.contents()).map_err(de::Error::custom)
    }
    pub fn serialize<S: Serializer>(
        value: &CertificateList,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let pem = Pem::new("X509 CRL", value.to_der().map_err(ser::Error::custom)?);
        serializer.serialize_str(&pem.to_string())
    }
}

pub mod u32_hex {
    use serde::Serializer;
    use zerocopy::AsBytes;

    type UInt32LE = zerocopy::little_endian::U32;

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<UInt32LE, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value: [u8; 4] = hex::deserialize(deserializer)?;
        Ok(value.into())
    }
    pub fn serialize<S: Serializer>(value: &UInt32LE, serializer: S) -> Result<S::Ok, S::Error> {
        hex::serialize(value.as_bytes(), serializer)
    }
}

/// Serde helper module for zerocopy::little_endian::U16
pub mod serde_little_endian_u16 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use zerocopy::little_endian;

    pub fn serialize<S>(value: &little_endian::U16, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value.get().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<little_endian::U16, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u16::deserialize(deserializer)?;
        Ok(little_endian::U16::new(value))
    }
}

/// Serde helper module for zerocopy::little_endian::U32
pub mod serde_little_endian_u32 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use zerocopy::little_endian;

    pub fn serialize<S>(value: &little_endian::U32, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value.get().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<little_endian::U32, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u32::deserialize(deserializer)?;
        Ok(little_endian::U32::new(value))
    }
}

/// Serde helper module for small byte arrays (specifically [u8; 6] for FMSPC)
pub mod serde_arrays {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(value: &[u8; 6], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 6], D::Error>
    where
        D: Deserializer<'de>,
    {
        <[u8; 6]>::deserialize(deserializer)
    }
}

pub mod cert_chain_processor {
    use x509_cert::{
        certificate::CertificateInner,
        der::{Decode, DecodePem},
    };

    /// A minimal function that returns ONLY certificate byte ranges
    /// This avoids any parsing to stay under BPF stack limits
    pub fn find_certificate_ranges(pem_data: &[u8]) -> Vec<(usize, usize)> {
        let mut ranges = Vec::new();
        let mut i = 0;

        while i < pem_data.len() {
            // Find BEGIN marker
            if let Some(begin_idx) = find_next_match(&pem_data[i..], b"-----BEGIN CERTIFICATE-----")
            {
                let begin_pos = i + begin_idx;

                // Find END marker
                if let Some(end_rel_idx) =
                    find_next_match(&pem_data[begin_pos + 27..], b"-----END CERTIFICATE-----")
                {
                    let end_pos = begin_pos + 27 + end_rel_idx + 25;

                    // Store range rather than content
                    ranges.push((begin_pos, end_pos));

                    // Move past this certificate
                    i = end_pos;
                } else {
                    // Incomplete certificate, move past the BEGIN marker
                    i = begin_pos + 27;
                }
            } else {
                // No more certificates
                break;
            }
        }

        ranges
    }

    // Simple byte matcher with no allocation
    fn find_next_match(data: &[u8], pattern: &[u8]) -> Option<usize> {
        if pattern.len() > data.len() {
            return None;
        }

        'outer: for i in 0..=(data.len() - pattern.len()) {
            for (j, &p) in pattern.iter().enumerate() {
                if data[i + j] != p {
                    continue 'outer;
                }
            }
            return Some(i);
        }

        None
    }

    /// Process a single certificate at the specified range
    fn parse_single_cert(
        pem_data: &[u8],
        range: (usize, usize),
    ) -> anyhow::Result<CertificateInner> {
        let (start, end) = range;
        if start >= pem_data.len() || end > pem_data.len() || start >= end {
            return Err(anyhow::anyhow!("Invalid certificate range"));
        }

        let cert_slice = &pem_data[start..end];

        // Try PEM format first
        if let Ok(cert) = CertificateInner::from_pem(cert_slice) {
            return Ok(cert);
        }

        // Try DER format as fallback (if this was base64 decoded already)
        CertificateInner::from_der(cert_slice)
            .map_err(|e| anyhow::anyhow!("Failed to parse certificate: {}", e))
    }

    /// Load certificate chain in chunks to avoid stack issues
    pub fn load_pem_chain_bpf_friendly(pem_data: &[u8]) -> anyhow::Result<Vec<CertificateInner>> {
        // Find all certificate ranges without parsing
        let ranges = find_certificate_ranges(pem_data);
        if ranges.is_empty() {
            return Err(anyhow::anyhow!("No certificates found"));
        }

        // Process each certificate individually
        let mut certificates = Vec::with_capacity(ranges.len());
        for range in ranges {
            // Each certificate is processed in isolation to minimize stack usage
            let cert = parse_single_cert(pem_data, range)?;
            certificates.push(cert);
        }

        Ok(certificates)
    }

    /// Load first certificate from pem data
    pub fn load_first_cert_from_pem_data(pem_data: &[u8]) -> anyhow::Result<CertificateInner> {
        let ranges = find_certificate_ranges(pem_data);
        if ranges.is_empty() {
            return Err(anyhow::anyhow!("No certificates found"));
        }
        parse_single_cert(pem_data, ranges[0])
    }
}

pub trait Expireable {
    fn valid_at(&self, timestamp: SystemTime) -> bool;
}

impl Expireable for CertificateList {
    /// Validate CRL creation/expiration
    fn valid_at(&self, timestamp: SystemTime) -> bool {
        if let Some(na) = self.tbs_cert_list.next_update.map(|t| t.to_system_time()) {
            if na <= timestamp {
                return false;
            }
        }

        // return false if the crl is for the future
        let nb = self.tbs_cert_list.this_update.to_system_time();
        if nb >= timestamp {
            return false;
        }

        true
    }
}

impl Expireable for CertificateInner {
    /// Validate a single certificate not_before/not_after
    fn valid_at(&self, timestamp: SystemTime) -> bool {
        let nb = self.tbs_certificate.validity.not_before.to_system_time();
        let na = self.tbs_certificate.validity.not_after.to_system_time();
        !(timestamp <= nb || na <= timestamp)
    }
}

impl Expireable for &[CertificateInner] {
    fn valid_at(&self, timestamp: SystemTime) -> bool {
        self.iter().all(|cert| cert.valid_at(timestamp))
    }
}

impl Expireable for Vec<CertificateInner> {
    fn valid_at(&self, timestamp: SystemTime) -> bool {
        self.as_slice().valid_at(timestamp)
    }
}

/// Removes `std::mem::size_of<T>()` bytes from the front of `bytes` and returns it as a `T`.
///
/// Returns `None` and leaves `bytes` unchanged if it isn't long enough.
pub fn read_from_bytes<T: zerocopy::FromBytes>(bytes: &mut &[u8]) -> Option<T> {
    let front = T::read_from_prefix(bytes)?;
    *bytes = &bytes[std::mem::size_of::<T>()..];
    Some(front)
}

/// Removes a slice of `size` from the front of `bytes` and returns it
///
/// Note: Caller must ensure that the slice is large enough
pub fn read_bytes<'a>(bytes: &mut &'a [u8], size: usize) -> &'a [u8] {
    let (front, rest) = bytes.split_at(size);
    *bytes = rest;
    front
}
