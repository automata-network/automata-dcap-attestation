// src/types/pod/enclave_identity/zero_copy/structs.rs

use super::error::ZeroCopyError;
use super::iterators::{AdvisoryIdIter, QeTcbLevelIter}; // Will define iterators later
use crate::types::pod::enclave_identity::{EnclaveIdentityHeader, QeTcbLevelPodHeader};
use bytemuck::Pod;

// Helper to cast slices (can be moved to a shared util if used more widely)
#[inline]
fn cast_slice<T: Pod>(slice: &[u8]) -> Result<&T, ZeroCopyError> {
    bytemuck::try_from_bytes(slice).map_err(ZeroCopyError::from_bytemuck_error)
}

fn decode_hex_array<const N: usize>(value: &[u8]) -> Result<[u8; N], ZeroCopyError> {
    let bytes = hex::decode(value).map_err(|_| ZeroCopyError::InvalidHex)?;
    bytes
        .try_into()
        .map_err(|_| ZeroCopyError::InvalidFieldLength)
}

// --- Top-Level ZeroCopy Struct ---

#[derive(Debug, Copy, Clone)]
pub struct EnclaveIdentityZeroCopy<'a> {
    pub header: &'a EnclaveIdentityHeader,
    tcb_levels_section_payload: &'a [u8], // Payload for all QeTcbLevel items
}

impl<'a> EnclaveIdentityZeroCopy<'a> {
    /// Creates a zero-copy view from a byte slice that starts with EnclaveIdentityHeader
    /// and is followed by its complete payload.
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ZeroCopyError> {
        if bytes.len() < core::mem::size_of::<EnclaveIdentityHeader>() {
            return Err(ZeroCopyError::InvalidSliceLength);
        }
        let (header_bytes, main_payload) =
            bytes.split_at(core::mem::size_of::<EnclaveIdentityHeader>());
        let header: &EnclaveIdentityHeader = cast_slice(header_bytes)?;

        let levels_len = header.tcb_levels_total_payload_len as usize;
        let tcb_levels_section_payload = main_payload
            .get(0..levels_len)
            .ok_or(ZeroCopyError::InvalidSliceLength)?;

        if levels_len > main_payload.len() {
            return Err(ZeroCopyError::InvalidSliceLength);
        }

        Ok(Self {
            header,
            tcb_levels_section_payload,
        })
    }

    // --- Direct Header Accessors ---
    pub fn id_byte(&self) -> u8 {
        self.header.id
    }
    pub fn version(&self) -> u32 {
        self.header.version
    }
    pub fn issue_date_timestamp(&self) -> i64 {
        self.header.issue_date_timestamp
    }
    pub fn next_update_timestamp(&self) -> i64 {
        self.header.next_update_timestamp
    }
    pub fn tcb_evaluation_data_number(&self) -> u32 {
        self.header.tcb_evaluation_data_number
    }
    pub fn isvprodid(&self) -> u16 {
        self.header.isvprodid
    }
    pub fn miscselect_bytes(&self) -> Result<[u8; 4], ZeroCopyError> {
        decode_hex_array(&self.header.miscselect_hex)
    }
    pub fn miscselect_mask_bytes(&self) -> Result<[u8; 4], ZeroCopyError> {
        decode_hex_array(&self.header.miscselect_mask_hex)
    }
    pub fn attributes_bytes(&self) -> Result<[u8; 16], ZeroCopyError> {
        decode_hex_array(&self.header.attributes_hex)
    }
    pub fn attributes_mask_bytes(&self) -> Result<[u8; 16], ZeroCopyError> {
        decode_hex_array(&self.header.attributes_mask_hex)
    }
    pub fn mrsigner_bytes(&self) -> Result<[u8; 32], ZeroCopyError> {
        decode_hex_array(&self.header.mrsigner_hex)
    }

    // --- Parsed/Structured Accessors ---
    pub fn tcb_levels_count(&self) -> u32 {
        self.header.tcb_levels_count
    }
    pub fn tcb_levels(&self) -> QeTcbLevelIter<'a> {
        QeTcbLevelIter::new(
            self.tcb_levels_section_payload,
            self.header.tcb_levels_count,
        )
    }
}

// --- QeTcbLevelZeroCopy ---
#[derive(Debug, Copy, Clone)]
pub struct QeTcbLevelZeroCopy<'a> {
    header: &'a QeTcbLevelPodHeader,
    advisory_ids_lengths_payload: &'a [u8],
    advisory_ids_data_payload: &'a [u8],
}

impl<'a> QeTcbLevelZeroCopy<'a> {
    // 'payload' is specific to this QeTcbLevel's advisory IDs (lengths array + data)
    pub fn new(header: &'a QeTcbLevelPodHeader, payload: &'a [u8]) -> Result<Self, ZeroCopyError> {
        let lengths_len = header.advisory_ids_lengths_array_len as usize;
        let data_len = header.advisory_ids_data_total_len as usize;

        let total_adv_payload_len = lengths_len
            .checked_add(data_len)
            .ok_or(ZeroCopyError::InvalidOffset)?;
        if total_adv_payload_len > payload.len() {
            return Err(ZeroCopyError::InvalidSliceLength);
        }

        Ok(Self {
            header,
            advisory_ids_lengths_payload: &payload[..lengths_len],
            advisory_ids_data_payload: &payload[lengths_len..lengths_len + data_len],
        })
    }

    pub fn isvsvn(&self) -> u16 {
        self.header.isvsvn
    }
    pub fn tcb_status_byte(&self) -> u8 {
        self.header.tcb_status
    }
    pub fn tcb_date_timestamp(&self) -> i64 {
        self.header.tcb_date_timestamp
    }
    pub fn advisory_ids_count(&self) -> u32 {
        self.header.advisory_ids_count
    }

    pub fn advisory_ids(&self) -> AdvisoryIdIter<'a> {
        AdvisoryIdIter::new(
            self.advisory_ids_lengths_payload,
            self.advisory_ids_data_payload,
            self.header.advisory_ids_count,
        )
    }
}
