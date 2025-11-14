use super::zero_copy::TcbInfoZeroCopy;
use super::zero_copy::conversion::tcb_info_from_zero_copy;
use super::{
    TcbInfoHeader, TcbLevelHeader, TdxModuleIdentityHeader, TdxModulePodData, TdxTcbLevelHeader,
};
use crate::types::tcb_info::{Tcb, TcbInfo};

use bytemuck::Zeroable;
use core::mem; // For align_of

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

// Helper function to copy string to fixed-size byte array, null-padding if shorter, truncating if longer.
fn string_to_fixed_bytes<const N: usize>(s: &str) -> [u8; N] {
    let mut arr = [0u8; N];
    let bytes = s.as_bytes();
    let len = bytes.len().min(N);
    arr[..len].copy_from_slice(&bytes[..len]);
    arr
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

/// Represents the combined TCB Info Header and its serialized payload.
pub struct SerializedTcbInfo {
    pub header: TcbInfoHeader,
    pub payload: Vec<u8>,
}

impl SerializedTcbInfo {
    /// Creates a SerializedTcbInfo from an application-level TcbInfo struct.
    pub fn from_rust_tcb_info(rust_tcb_info: &TcbInfo) -> Result<Self, String> {
        let mut header = TcbInfoHeader::zeroed();
        let mut payload_bytes = Vec::new();
        let mut current_payload_offset = 0;

        header.id_type = string_to_fixed_bytes::<6>(rust_tcb_info.id.as_deref().unwrap_or(""));
        header.version = rust_tcb_info.version as u32; // TcbInfoVersion derives Copy
        header.issue_date_timestamp = rust_tcb_info.issue_date.timestamp();
        header.next_update_timestamp = rust_tcb_info.next_update.timestamp();
        header.fmspc_hex = hex_chars_to_fixed_bytes::<12>(&rust_tcb_info.fmspc);
        header.pce_id_hex = hex_chars_to_fixed_bytes::<4>(&rust_tcb_info.pce_id);
        header.tcb_type = rust_tcb_info.tcb_type;
        header.tcb_evaluation_data_number = rust_tcb_info.tcb_evaluation_data_number;

        if let Some(tdx_module) = &rust_tcb_info.tdx_module {
            header.tdx_module_present = 1;
            let pod_data = TdxModulePodData {
                mrsigner_hex: hex_chars_to_fixed_bytes::<96>(&tdx_module.mrsigner),
                attributes_hex: hex_chars_to_fixed_bytes::<16>(&tdx_module.attributes),
                attributes_mask_hex: hex_chars_to_fixed_bytes::<16>(&tdx_module.attributes_mask),
            };
            let tdx_module_bytes = bytemuck::bytes_of(&pod_data);
            payload_bytes.extend_from_slice(tdx_module_bytes);
            header.tdx_module_data_len = tdx_module_bytes.len() as u32;
            current_payload_offset += tdx_module_bytes.len();
        } else {
            header.tdx_module_present = 0;
            header.tdx_module_data_len = 0;
        }

        let tdx_module_identities_payload_start = current_payload_offset;
        if let Some(identities) = &rust_tcb_info.tdx_module_identities {
            header.tdx_module_identities_count = identities.len() as u32;
            for identity in identities {
                let mut identity_header = TdxModuleIdentityHeader::zeroed();
                identity_header.mrsigner_hex = hex_chars_to_fixed_bytes::<96>(&identity.mrsigner);
                identity_header.attributes_hex =
                    hex_chars_to_fixed_bytes::<16>(&identity.attributes);
                identity_header.attributes_mask_hex =
                    hex_chars_to_fixed_bytes::<16>(&identity.attributes_mask);

                let id_bytes = identity.id.as_bytes();
                identity_header.id_len = id_bytes.len() as u8;

                let mut tdx_tcb_levels_payload_for_identity = Vec::new();
                identity_header.tcb_levels_count = identity.tcb_levels.len() as u32;
                for tdx_tcb_level in &identity.tcb_levels {
                    let mut tdx_tcb_level_header = TdxTcbLevelHeader::zeroed();
                    tdx_tcb_level_header.tcb_isvsvn = tdx_tcb_level.tcb.isvsvn;
                    tdx_tcb_level_header.tcb_status = tdx_tcb_level.tcb_status as u8;
                    tdx_tcb_level_header.tcb_date_timestamp = tdx_tcb_level.tcb_date.timestamp();

                    let mut advisory_id_lengths_bytes = Vec::new();
                    let mut advisory_id_data_bytes = Vec::new();
                    if let Some(advisory_ids) = &tdx_tcb_level.advisory_ids {
                        tdx_tcb_level_header.advisory_ids_count = advisory_ids.len() as u32;
                        for adv_id in advisory_ids {
                            let adv_id_bytes = adv_id.as_bytes();
                            advisory_id_lengths_bytes
                                .extend_from_slice(&(adv_id_bytes.len() as u16).to_le_bytes());
                            advisory_id_data_bytes.extend_from_slice(adv_id_bytes);
                        }
                    } else {
                        tdx_tcb_level_header.advisory_ids_count = 0;
                    }
                    tdx_tcb_level_header.advisory_ids_lengths_array_len =
                        advisory_id_lengths_bytes.len() as u32;
                    tdx_tcb_level_header.advisory_ids_data_total_len =
                        advisory_id_data_bytes.len() as u32;

                    tdx_tcb_levels_payload_for_identity
                        .extend_from_slice(bytemuck::bytes_of(&tdx_tcb_level_header));
                    tdx_tcb_levels_payload_for_identity
                        .extend_from_slice(&advisory_id_lengths_bytes);
                    tdx_tcb_levels_payload_for_identity.extend_from_slice(&advisory_id_data_bytes);

                    // Add padding for the *next* TdxTcbLevelHeader in this sub-list
                    append_padding_to_align(
                        &mut tdx_tcb_levels_payload_for_identity,
                        mem::align_of::<TdxTcbLevelHeader>(), // Align to 8
                    );
                }
                identity_header.tcb_levels_total_payload_len =
                    tdx_tcb_levels_payload_for_identity.len() as u32;

                payload_bytes.extend_from_slice(bytemuck::bytes_of(&identity_header));
                current_payload_offset += mem::size_of::<TdxModuleIdentityHeader>();

                payload_bytes.extend_from_slice(id_bytes);
                current_payload_offset += id_bytes.len();

                // Ensure the start of the TdxTcbLevel list (which follows id_bytes) is 8-byte aligned,
                // as TdxTcbLevelHeader requires 8-byte alignment.
                let padding_for_tdx_tcb_level_list = append_padding_to_align(
                    &mut payload_bytes,
                    mem::align_of::<TdxTcbLevelHeader>(), // Align to 8
                );
                current_payload_offset += padding_for_tdx_tcb_level_list;

                payload_bytes.extend_from_slice(&tdx_tcb_levels_payload_for_identity);
                current_payload_offset += tdx_tcb_levels_payload_for_identity.len();

                // Add padding for the *next* TdxModuleIdentityHeader
                let padding_added_for_next_identity = append_padding_to_align(
                    &mut payload_bytes,
                    mem::align_of::<TdxModuleIdentityHeader>(), // Align to 4
                );
                current_payload_offset += padding_added_for_next_identity;
            }
        } else {
            header.tdx_module_identities_count = 0;
        }
        header.tdx_module_identities_total_payload_len =
            (current_payload_offset - tdx_module_identities_payload_start) as u32;

        let tcb_levels_payload_start = current_payload_offset;
        header.tcb_levels_count = rust_tcb_info.tcb_levels.len() as u32;
        for rust_tcb_level in &rust_tcb_info.tcb_levels {
            let mut tcb_level_header = TcbLevelHeader::zeroed();
            tcb_level_header.tcb_status = rust_tcb_level.tcb_status as u8;
            tcb_level_header.pce_svn = rust_tcb_level.tcb.pcesvn();
            tcb_level_header.tcb_date_timestamp = rust_tcb_level.tcb_date.timestamp();

            let mut sgx_components_payload_strings = Vec::new();
            let mut tdx_components_payload_strings_for_level = Vec::new();

            match &rust_tcb_level.tcb {
                Tcb::V3(tcb_v3) => {
                    for i in 0..16 {
                        let comp_header_ref = &mut tcb_level_header.sgx_tcb_components[i];
                        comp_header_ref.cpusvn = tcb_v3.sgxtcbcomponents[i].svn;
                        let cat_str = tcb_v3.sgxtcbcomponents[i].category.as_deref().unwrap_or("");
                        let type_str = tcb_v3.sgxtcbcomponents[i]
                            .component_type
                            .as_deref()
                            .unwrap_or("");
                        comp_header_ref.category_len = cat_str.len() as u8;
                        comp_header_ref.component_type_len = type_str.len() as u8;
                        sgx_components_payload_strings.extend_from_slice(cat_str.as_bytes());
                        sgx_components_payload_strings.extend_from_slice(type_str.as_bytes());
                    }
                    if let Some(tdx_comps_v3) = &tcb_v3.tdxtcbcomponents {
                        tcb_level_header.tdx_tcb_components_present = 1;
                        for (i, tdx_comp) in tdx_comps_v3.iter().enumerate().take(16) {
                            let comp_header_ref = &mut tcb_level_header.tdx_tcb_components[i];
                            comp_header_ref.cpusvn = tdx_comp.svn;
                            let cat_str = tdx_comp.category.as_deref().unwrap_or("");
                            let type_str = tdx_comp.component_type.as_deref().unwrap_or("");
                            comp_header_ref.category_len = cat_str.len() as u8;
                            comp_header_ref.component_type_len = type_str.len() as u8;
                            tdx_components_payload_strings_for_level
                                .extend_from_slice(cat_str.as_bytes());
                            tdx_components_payload_strings_for_level
                                .extend_from_slice(type_str.as_bytes());
                        }
                        tcb_level_header.tdx_components_strings_total_len =
                            tdx_components_payload_strings_for_level.len() as u32;
                    } else {
                        tcb_level_header.tdx_tcb_components_present = 0;
                        tcb_level_header.tdx_components_strings_total_len = 0;
                    }
                },
                Tcb::V2(_tcb_v2) => {
                    let svns = rust_tcb_level.tcb.sgx_tcb_components();
                    for (i, &svn) in svns.iter().enumerate() {
                        let comp_header_ref = &mut tcb_level_header.sgx_tcb_components[i];
                        comp_header_ref.cpusvn = svn;
                        comp_header_ref.category_len = 0;
                        comp_header_ref.component_type_len = 0;
                    }
                    tcb_level_header.tdx_tcb_components_present = 0;
                    tcb_level_header.tdx_components_strings_total_len = 0;
                },
            }
            tcb_level_header.sgx_components_strings_total_len =
                sgx_components_payload_strings.len() as u32;

            let mut tcb_level_advisory_id_lengths_bytes = Vec::new();
            let mut tcb_level_advisory_id_data_bytes = Vec::new();
            if let Some(advisory_ids) = &rust_tcb_level.advisory_ids {
                tcb_level_header.advisory_ids_count = advisory_ids.len() as u32;
                for adv_id in advisory_ids {
                    let adv_id_bytes = adv_id.as_bytes();
                    tcb_level_advisory_id_lengths_bytes
                        .extend_from_slice(&(adv_id_bytes.len() as u16).to_le_bytes());
                    tcb_level_advisory_id_data_bytes.extend_from_slice(adv_id_bytes);
                }
            } else {
                tcb_level_header.advisory_ids_count = 0;
            }
            tcb_level_header.advisory_ids_lengths_array_len =
                tcb_level_advisory_id_lengths_bytes.len() as u32;
            tcb_level_header.advisory_ids_data_total_len =
                tcb_level_advisory_id_data_bytes.len() as u32;

            payload_bytes.extend_from_slice(bytemuck::bytes_of(&tcb_level_header));
            current_payload_offset += core::mem::size_of::<TcbLevelHeader>();

            payload_bytes.extend_from_slice(&sgx_components_payload_strings);
            current_payload_offset += sgx_components_payload_strings.len();

            if tcb_level_header.tdx_tcb_components_present == 1 {
                payload_bytes.extend_from_slice(&tdx_components_payload_strings_for_level);
                current_payload_offset += tdx_components_payload_strings_for_level.len();
            }
            payload_bytes.extend_from_slice(&tcb_level_advisory_id_lengths_bytes);
            current_payload_offset += tcb_level_advisory_id_lengths_bytes.len();
            payload_bytes.extend_from_slice(&tcb_level_advisory_id_data_bytes);
            current_payload_offset += tcb_level_advisory_id_data_bytes.len();

            // Add padding for the *next* TcbLevelHeader
            let padding_added_for_next_tcb_level = append_padding_to_align(
                &mut payload_bytes,
                mem::align_of::<TcbLevelHeader>(), // Align to 8
            );
            current_payload_offset += padding_added_for_next_tcb_level;
        }
        header.tcb_levels_total_payload_len =
            (current_payload_offset - tcb_levels_payload_start) as u32;

        Ok(SerializedTcbInfo {
            header,
            payload: payload_bytes,
        })
    }
}

// --- TcbPod Serialization and Deserialization ---

/// Serializes a TcbPod into a byte vector.
/// The layout will be: signature | TcbInfoHeader | payload.
pub fn serialize_tcb_pod(serialized_tcb_info: &SerializedTcbInfo, signature: &[u8; 64]) -> Vec<u8> {
    let header_bytes = bytemuck::bytes_of(&serialized_tcb_info.header);
    let mut tcb_pod_bytes = Vec::with_capacity(
        signature.len() + header_bytes.len() + serialized_tcb_info.payload.len(),
    );
    tcb_pod_bytes.extend_from_slice(signature);
    tcb_pod_bytes.extend_from_slice(header_bytes);
    tcb_pod_bytes.extend_from_slice(&serialized_tcb_info.payload);
    tcb_pod_bytes
}

/// Parses a byte slice representing a TcbPod into an application-level TcbInfo and the signature.
/// Expects bytes in the layout: signature | TcbInfoHeader | payload.
pub fn parse_tcb_pod_bytes(pod_bytes: &[u8]) -> Result<(TcbInfo, [u8; 64]), String> {
    let min_len = core::mem::size_of::<[u8; 64]>() + core::mem::size_of::<TcbInfoHeader>();
    if pod_bytes.len() < min_len {
        return Err(format!(
            "Byte slice too short for TcbPod. Expected at least {} bytes, got {}",
            min_len,
            pod_bytes.len()
        ));
    }

    let signature_slice = pod_bytes
        .get(..64)
        .ok_or_else(|| "Failed to slice signature".to_string())?;
    let mut signature = [0u8; 64];
    signature.copy_from_slice(signature_slice);

    let tcb_info_and_payload_bytes = pod_bytes
        .get(64..)
        .ok_or_else(|| "Failed to slice TCB info header and payload".to_string())?;

    let tcb_info_view = TcbInfoZeroCopy::from_bytes(tcb_info_and_payload_bytes)
        .map_err(|e| format!("Failed to create TcbInfoZeroCopy: {:?}", e))?;

    let rust_tcb_info = tcb_info_from_zero_copy(&tcb_info_view)
        .map_err(|e| format!("Failed to convert TcbInfoZeroCopy to TcbInfo: {:?}", e))?;

    Ok((rust_tcb_info, signature))
}
