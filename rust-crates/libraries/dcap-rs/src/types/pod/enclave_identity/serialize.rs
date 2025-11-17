// src/types/pod/enclave_identity/serialize.rs

use super::zero_copy::{EnclaveIdentityZeroCopy, conversion::enclave_identity_from_zero_copy};
use super::{EnclaveIdentityHeader, QeTcbLevelPodHeader};
use crate::types::enclave_identity::{EnclaveIdentity, EnclaveType};

use bytemuck::Zeroable; // For zeroed() method
use core::mem;

// Helper function to append padding (null bytes) to `bytes_vec` so its new total length
// becomes a multiple of `align_to`.
// Returns the number of padding bytes that were added.
fn append_padding_to_align(bytes_vec: &mut Vec<u8>, align_to: usize) -> usize {
    let current_len = bytes_vec.len();
    let remainder = current_len % align_to;
    let mut padding_bytes_added = 0;
    if remainder != 0 {
        padding_bytes_added = align_to - remainder;
        for _ in 0..padding_bytes_added {
            bytes_vec.push(0); // Add null bytes for padding
        }
    }
    padding_bytes_added
}

// Helper function to copy a hex string's ASCII characters to a fixed-size byte array.
// It null-pads if the string is shorter and truncates if longer.
fn hex_chars_to_fixed_bytes<const N: usize>(hex_s: &str) -> [u8; N] {
    let mut arr = [0u8; N];
    let s_bytes = hex_s.as_bytes();
    let len_to_copy = s_bytes.len().min(N);
    arr[..len_to_copy].copy_from_slice(&s_bytes[..len_to_copy]);
    arr
}

// Helper to convert EnclaveType to its u8 representation
fn enclave_type_to_byte(enclave_type: &EnclaveType) -> u8 {
    match enclave_type {
        EnclaveType::Qe => 0,
        EnclaveType::Qve => 1,
        EnclaveType::TdQe => 2,
    }
}

// Helper to convert QeTcbStatus to its u8 representation
// This mirrors the mapping in zero_copy/conversion.rs qe_tcb_status_from_byte
fn qe_tcb_status_to_byte(status: &crate::types::enclave_identity::QeTcbStatus) -> u8 {
    match status {
        crate::types::enclave_identity::QeTcbStatus::UpToDate => 0,
        crate::types::enclave_identity::QeTcbStatus::SWHardeningNeeded => 1,
        crate::types::enclave_identity::QeTcbStatus::OutOfDate => 2,
        crate::types::enclave_identity::QeTcbStatus::OutOfDateConfigurationNeeded => 3,
        crate::types::enclave_identity::QeTcbStatus::ConfigurationNeeded => 4,
        crate::types::enclave_identity::QeTcbStatus::ConfigurationAndSWHardeningNeeded => 5,
        crate::types::enclave_identity::QeTcbStatus::Revoked => 6,
        crate::types::enclave_identity::QeTcbStatus::Unspecified => 7,
    }
}

/// Represents the combined Enclave Identity Header and its serialized payload.
pub struct SerializedEnclaveIdentity {
    pub header: EnclaveIdentityHeader,
    pub payload: Vec<u8>,
}

impl SerializedEnclaveIdentity {
    /// Creates a SerializedEnclaveIdentity from an application-level EnclaveIdentity struct.
    pub fn from_rust_enclave_identity(rust_ei: &EnclaveIdentity) -> Result<Self, String> {
        let mut header = EnclaveIdentityHeader::zeroed(); // Requires Zeroable
        let mut payload_bytes = Vec::new();
        let mut current_payload_offset = 0;

        header.id = enclave_type_to_byte(&rust_ei.id);
        header.version = rust_ei.version;
        header.issue_date_timestamp = rust_ei.issue_date.timestamp();
        header.next_update_timestamp = rust_ei.next_update.timestamp();
        header.tcb_evaluation_data_number = rust_ei.tcb_evaluation_data_number;
        header.isvprodid = rust_ei.isvprodid;

        header.miscselect_hex = hex_chars_to_fixed_bytes::<8>(&rust_ei.miscselect);
        header.miscselect_mask_hex = hex_chars_to_fixed_bytes::<8>(&rust_ei.miscselect_mask);
        header.attributes_hex = hex_chars_to_fixed_bytes::<32>(&rust_ei.attributes);
        header.attributes_mask_hex = hex_chars_to_fixed_bytes::<32>(&rust_ei.attributes_mask);
        header.mrsigner_hex = hex_chars_to_fixed_bytes::<64>(&rust_ei.mrsigner);

        let tcb_levels_payload_start_offset = current_payload_offset;
        header.tcb_levels_count = rust_ei.tcb_levels.len() as u32;

        for rust_tcb_level in &rust_ei.tcb_levels {
            let mut qe_tcb_level_header = QeTcbLevelPodHeader::zeroed(); // Requires Zeroable
            qe_tcb_level_header.isvsvn = rust_tcb_level.tcb.isvsvn;
            qe_tcb_level_header.tcb_status = qe_tcb_status_to_byte(&rust_tcb_level.tcb_status);
            qe_tcb_level_header.tcb_date_timestamp = rust_tcb_level.tcb_date.timestamp();

            let mut advisory_id_lengths_bytes = Vec::new();
            let mut advisory_id_data_bytes = Vec::new();

            if let Some(advisory_ids) = &rust_tcb_level.advisory_ids {
                qe_tcb_level_header.advisory_ids_count = advisory_ids.len() as u32;
                for adv_id in advisory_ids {
                    let adv_id_bytes = adv_id.as_bytes();
                    advisory_id_lengths_bytes
                        .extend_from_slice(&(adv_id_bytes.len() as u16).to_le_bytes());
                    advisory_id_data_bytes.extend_from_slice(adv_id_bytes);
                }
            } else {
                qe_tcb_level_header.advisory_ids_count = 0;
            }
            qe_tcb_level_header.advisory_ids_lengths_array_len =
                advisory_id_lengths_bytes.len() as u32;
            qe_tcb_level_header.advisory_ids_data_total_len = advisory_id_data_bytes.len() as u32;

            payload_bytes.extend_from_slice(bytemuck::bytes_of(&qe_tcb_level_header));
            current_payload_offset += mem::size_of::<QeTcbLevelPodHeader>();

            payload_bytes.extend_from_slice(&advisory_id_lengths_bytes);
            current_payload_offset += advisory_id_lengths_bytes.len();

            payload_bytes.extend_from_slice(&advisory_id_data_bytes);
            current_payload_offset += advisory_id_data_bytes.len();

            // Add padding for the *next* QeTcbLevelPodHeader
            let padding_added = append_padding_to_align(
                &mut payload_bytes,
                mem::align_of::<QeTcbLevelPodHeader>(), // Align to 8
            );
            current_payload_offset += padding_added;
        }
        header.tcb_levels_total_payload_len =
            (current_payload_offset - tcb_levels_payload_start_offset) as u32;

        Ok(SerializedEnclaveIdentity {
            header,
            payload: payload_bytes,
        })
    }
}

/// Serializes an EnclaveIdentityPod into a byte vector.
/// The layout will be: signature | EnclaveIdentityHeader | payload.
pub fn serialize_enclave_identity_pod(
    serialized_ei: &SerializedEnclaveIdentity,
    signature: &[u8; 64],
) -> Vec<u8> {
    let header_bytes = bytemuck::bytes_of(&serialized_ei.header);
    let mut pod_bytes =
        Vec::with_capacity(signature.len() + header_bytes.len() + serialized_ei.payload.len());
    pod_bytes.extend_from_slice(signature);
    pod_bytes.extend_from_slice(header_bytes);
    pod_bytes.extend_from_slice(&serialized_ei.payload);
    pod_bytes
}

/// Parses a byte slice representing an EnclaveIdentityPod into an application-level EnclaveIdentity and the signature.
/// Expects bytes in the layout: signature | EnclaveIdentityHeader | payload.
pub fn parse_enclave_identity_pod_bytes(
    pod_bytes: &[u8],
) -> Result<(EnclaveIdentity, [u8; 64]), String> {
    let signature_len = 64;
    let header_len = mem::size_of::<EnclaveIdentityHeader>();
    let min_len = signature_len + header_len;

    if pod_bytes.len() < min_len {
        return Err(format!(
            "Byte slice too short for EnclaveIdentityPod. Expected at least {} bytes, got {}",
            min_len,
            pod_bytes.len()
        ));
    }

    let signature_slice = pod_bytes
        .get(..signature_len)
        .ok_or_else(|| "Failed to slice signature".to_string())?;
    let mut signature = [0u8; 64];
    signature.copy_from_slice(signature_slice);

    let ei_header_and_payload_bytes = pod_bytes
        .get(signature_len..)
        .ok_or_else(|| "Failed to slice Enclave Identity header and payload".to_string())?;

    // This part uses the zero-copy parsing and then converts to the rich Rust struct.
    // This ensures that the parsing logic (especially for complex payloads) is centralized
    // in the zero_copy module.
    let ei_zero_copy_view = EnclaveIdentityZeroCopy::from_bytes(ei_header_and_payload_bytes)
        .map_err(|e| format!("Failed to create EnclaveIdentityZeroCopy view: {:?}", e))?;

    let rust_ei = enclave_identity_from_zero_copy(&ei_zero_copy_view).map_err(|e| {
        format!(
            "Failed to convert EnclaveIdentityZeroCopy to EnclaveIdentity: {:?}",
            e
        )
    })?;

    Ok((rust_ei, signature))
}
