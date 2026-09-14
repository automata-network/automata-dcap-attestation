//! Canonical DCAP output/journal schema 2.1, independent of the Intel quote version.
use alloy_sol_types::SolValue;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

pub const OUTPUT_V2_HEADER_LENGTH: usize = 289;
pub const OUTPUT_V2_MAX_LENGTH: usize = u16::MAX as usize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedOutputV2 {
    pub format_major_version: u16,
    pub format_minor_version: u16,
    pub quote_version: u16,
    pub quote_body_type: u16,
    pub tcb_status: u8,
    pub fmspc: [u8; 6],
    pub ppid: [u8; 16],
    pub piid: [u8; 16],
    pub piid_present: bool,
    pub timestamp: u64,
    /// TCB Info, QE Identity, root cert, signing cert, root CRL, PCK CRL (in that order).
    pub collateral_hashes: [[u8; 32]; 6],
    /// SHA-256 of the complete input quote, not Keccak-256.
    pub full_quote_hash: [u8; 32],
    pub quote_body: Vec<u8>,
    pub advisory_ids: Vec<String>,
}

impl VerifiedOutputV2 {
    fn body_length(quote_version: u16, body_type: u16) -> Result<usize> {
        ensure!(
            (3..=5).contains(&quote_version),
            "unsupported quote version"
        );
        ensure!((1..=3).contains(&body_type), "unsupported quote body type");
        ensure!(quote_version != 3 || body_type == 1, "V3 must contain SGX");
        ensure!(
            quote_version != 4 || body_type != 3,
            "V4 cannot contain TD 1.5"
        );
        Ok(match body_type {
            1 => 384,
            2 => 584,
            _ => 648,
        })
    }

    pub fn to_vec(&self) -> Result<Vec<u8>> {
        ensure!(
            self.format_major_version == 2 && self.format_minor_version == 1,
            "unsupported output schema"
        );
        ensure!(self.tcb_status <= 9, "unknown TCB status");
        ensure!(
            self.piid_present || self.piid == [0; 16],
            "absent PIID must be zero"
        );
        let body_len = Self::body_length(self.quote_version, self.quote_body_type)?;
        ensure!(self.quote_body.len() == body_len, "invalid body length");
        let advisory = if self.advisory_ids.is_empty() {
            Vec::new()
        } else {
            self.advisory_ids.abi_encode()
        };
        let total = OUTPUT_V2_HEADER_LENGTH + body_len + advisory.len();
        ensure!(
            total <= OUTPUT_V2_MAX_LENGTH,
            "output exceeds uint16 length"
        );
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&2u16.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.push(6); // Legacy TCB-status offset guard, NOT the verified status.
        out.extend_from_slice(&self.quote_version.to_be_bytes());
        out.extend_from_slice(&self.quote_body_type.to_be_bytes());
        out.push(self.tcb_status);
        out.extend_from_slice(&self.fmspc);
        out.extend_from_slice(&self.ppid);
        out.extend_from_slice(&self.piid);
        out.push(u8::from(self.piid_present));
        out.extend_from_slice(&(OUTPUT_V2_HEADER_LENGTH as u16).to_be_bytes());
        out.extend_from_slice(&(body_len as u16).to_be_bytes());
        let advisory_offset = if advisory.is_empty() {
            0
        } else {
            OUTPUT_V2_HEADER_LENGTH + body_len
        };
        out.extend_from_slice(&(advisory_offset as u16).to_be_bytes());
        out.extend_from_slice(&(advisory.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        for hash in &self.collateral_hashes {
            out.extend_from_slice(hash);
        }
        out.extend_from_slice(&self.full_quote_hash);
        out.extend_from_slice(&self.quote_body);
        out.extend_from_slice(&advisory);
        Ok(out)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        ensure!(
            (OUTPUT_V2_HEADER_LENGTH..=OUTPUT_V2_MAX_LENGTH).contains(&data.len()),
            "invalid output length"
        );
        let u16_at = |offset| u16::from_be_bytes([data[offset], data[offset + 1]]);
        ensure!(
            u16_at(0) == 2 && u16_at(2) == 1 && data[4] == 6,
            "unsupported output header"
        );
        ensure!(
            data[9] <= 9 && data[48] <= 1,
            "invalid status or presence flag"
        );
        let quote_version = u16_at(5);
        let quote_body_type = u16_at(7);
        let body_len = Self::body_length(quote_version, quote_body_type)?;
        let body_end = OUTPUT_V2_HEADER_LENGTH + body_len;
        ensure!(
            u16_at(49) as usize == OUTPUT_V2_HEADER_LENGTH && u16_at(51) as usize == body_len,
            "invalid body offsets"
        );
        ensure!(body_end <= data.len(), "truncated body");
        let advisory_offset = u16_at(53) as usize;
        let advisory_len = u16_at(55) as usize;
        let advisory_ids = if advisory_len == 0 {
            ensure!(
                advisory_offset == 0 && data.len() == body_end,
                "noncanonical empty advisory payload"
            );
            Vec::new()
        } else {
            ensure!(
                advisory_offset == body_end && advisory_offset + advisory_len == data.len(),
                "noncanonical advisory offsets"
            );
            let ids = Vec::<String>::abi_decode(&data[body_end..])?;
            ensure!(
                !ids.is_empty() && ids.abi_encode() == data[body_end..],
                "noncanonical advisory ABI"
            );
            ids
        };
        let mut collateral_hashes = [[0; 32]; 6];
        for (i, hash) in collateral_hashes.iter_mut().enumerate() {
            hash.copy_from_slice(&data[65 + 32 * i..97 + 32 * i]);
        }
        let result = Self {
            format_major_version: 2,
            format_minor_version: 1,
            quote_version,
            quote_body_type,
            tcb_status: data[9],
            fmspc: data[10..16].try_into()?,
            ppid: data[16..32].try_into()?,
            piid: data[32..48].try_into()?,
            piid_present: data[48] == 1,
            timestamp: u64::from_be_bytes(data[57..65].try_into()?),
            collateral_hashes,
            full_quote_hash: data[257..289].try_into()?,
            quote_body: data[289..body_end].to_vec(),
            advisory_ids,
        };
        ensure!(
            result.piid_present || result.piid == [0; 16],
            "absent PIID must be zero"
        );
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn example() -> VerifiedOutputV2 {
        VerifiedOutputV2 {
            format_major_version: 2,
            format_minor_version: 1,
            quote_version: 3,
            quote_body_type: 1,
            tcb_status: 0,
            fmspc: [0x11; 6],
            ppid: [0; 16],
            piid: [0; 16],
            piid_present: false,
            timestamp: 0x0102030405060708,
            collateral_hashes: [[0x22; 32]; 6],
            full_quote_hash: [0x33; 32],
            quote_body: vec![0x44; 384],
            advisory_ids: vec![],
        }
    }
    #[test]
    fn roundtrip_all_bodies_and_advisories() {
        for (version, body, len) in [
            (3, 1, 384),
            (4, 1, 384),
            (4, 2, 584),
            (5, 1, 384),
            (5, 2, 584),
            (5, 3, 648),
        ] {
            for ids in [
                vec![],
                vec![
                    "INTEL-SA-00001".into(),
                    "é证书".into(),
                    "INTEL-SA-00001".into(),
                ],
            ] {
                let mut out = example();
                out.quote_version = version;
                out.quote_body_type = body;
                out.quote_body = vec![0x44; len];
                out.advisory_ids = ids;
                let data = out.to_vec().unwrap();
                assert_eq!(&data[..5], &[0, 2, 0, 1, 6]);
                assert_eq!(&data[49..51], &289u16.to_be_bytes());
                assert_eq!(VerifiedOutputV2::from_bytes(&data).unwrap(), out);
            }
        }
    }
    #[test]
    fn rejects_mutations_and_all_truncations() {
        let data = example().to_vec().unwrap();
        for end in 0..data.len() {
            assert!(VerifiedOutputV2::from_bytes(&data[..end]).is_err());
        }
        for (offset, value) in [
            (0, 1),
            (3, 2),
            (4, 0),
            (9, 10),
            (48, 2),
            (32, 1),
            (49, 0),
            (51, 0),
            (53, 1),
            (56, 1),
        ] {
            let mut bad = data.clone();
            bad[offset] = value;
            assert!(
                VerifiedOutputV2::from_bytes(&bad).is_err(),
                "offset {offset}"
            );
        }
        let mut bad = data.clone();
        bad.push(0);
        assert!(VerifiedOutputV2::from_bytes(&bad).is_err());
    }
    #[test]
    fn preserves_zero_identity_and_relaunch_status() {
        let mut out = example();
        out.piid_present = true;
        out.tcb_status = 9;
        assert_eq!(
            VerifiedOutputV2::from_bytes(&out.to_vec().unwrap()).unwrap(),
            out
        );
    }
    #[test]
    fn rejects_oversize_and_noncanonical_advisory() {
        let mut out = example();
        out.advisory_ids = vec!["a".repeat(65535)];
        assert!(out.to_vec().is_err());
        out.advisory_ids = vec!["a".into()];
        let mut data = out.to_vec().unwrap();
        *data.last_mut().unwrap() = 1;
        assert!(VerifiedOutputV2::from_bytes(&data).is_err());
    }
}
