use bytemuck::{Pod, Zeroable};

pub mod zero_copy;

// Conditionally import serialization and tests based on features
#[cfg(feature = "full")]
pub mod serialize;

#[cfg(all(test, not(feature = "zero-copy")))]
mod tests;

// --- POD Structs for Enclave Identity ---

/// Header for a Quoting Enclave (QE) TCB Level.
/// The actual advisory ID strings and their lengths array will be in this header's payload.
/// Alignment: 8 bytes (due to i64)
#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable)] // Removed Default, not needed for bytemuck if zeroed
pub struct QeTcbLevelPodHeader {
    pub isvsvn: u16,
    pub tcb_status: u8,     // Represents QeTcbStatus enum
    pub _padding0: [u8; 5], // Align to 8 for tcb_date_timestamp
    pub tcb_date_timestamp: i64,
    pub advisory_ids_count: u32,
    pub advisory_ids_lengths_array_len: u32, // Total byte length of the array of u16 lengths
    pub advisory_ids_data_total_len: u32, // Total byte length of concatenated advisory ID strings
    pub _padding1: [u8; 4],               // Ensure struct size is multiple of alignment (8)
}

/// Main header for Enclave Identity.
/// This is followed by a variable-length payload containing data for tcb_levels.
/// Alignment: 8 bytes (due to i64)
#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable)] // Removed Default
pub struct EnclaveIdentityHeader {
    pub id: u8,               // Represents EnclaveType enum (e.g., 0: Qe, 1: Qve, 2: TdQe)
    pub _padding_id: [u8; 3], // Align to 4 for version
    pub version: u32,
    pub issue_date_timestamp: i64,
    pub next_update_timestamp: i64,
    pub tcb_evaluation_data_number: u32,
    pub isvprodid: u16,
    pub _final_padding: [u8; 2],
    // Hex strings (fixed-size byte arrays storing UTF-8 hex characters)
    pub miscselect_hex: [u8; 8],
    pub miscselect_mask_hex: [u8; 8],
    pub attributes_hex: [u8; 32],
    pub attributes_mask_hex: [u8; 32],
    pub mrsigner_hex: [u8; 64],

    pub tcb_levels_count: u32,
    pub tcb_levels_total_payload_len: u32, // Total byte length for all QeTcbLevelPodHeader sections + their payloads
                                           // Ensure total size is a multiple of 8 (max alignment of fields)
                                           // Current size before this padding:
                                           // id (1) + pad_id (3) = 4
                                           // version (4) = 4
                                           // issue_date (8) = 8
                                           // next_update (8) = 8
                                           // tcb_eval_num (4) = 4
                                           // isvprodid (2) + _final_padding (2) = 4
                                           // miscselect (8) = 8
                                           // miscselect_mask (8) = 8
                                           // attributes (32) = 32
                                           // attributes_mask (32) = 32
                                           // mrsigner (64) = 64
                                           // tcb_levels_count (4) = 4
                                           // tcb_levels_total_payload_len (4) = 4
                                           // Total = 4+4+8+8+4+4+8+8+32+32+64+4+4 = 184
}

/// The top-level POD structure for Enclave Identity and its signature.
/// The variable payload for EnclaveIdentityHeader follows it directly in memory.
/// Alignment: 8 bytes (due to EnclaveIdentityHeader)
#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable)]
pub struct EnclaveIdentityPod {
    pub signature: [u8; 64], // Assuming P256 ECDSA signature
    pub enclave_identity_header: EnclaveIdentityHeader,
    // The variable payload associated with enclave_identity_header follows here in memory.
}

// Compile-time assertions for struct sizes and alignments (optional but good practice)
#[cfg(test)]
mod pod_layout_tests {
    use super::*;
    use core::mem::{align_of, size_of};

    #[test]
    fn check_qe_tcb_level_pod_header_layout() {
        assert_eq!(size_of::<QeTcbLevelPodHeader>(), 32); // 2+1+5 + 8 + 4+4+4 + 4 = 32
        assert_eq!(align_of::<QeTcbLevelPodHeader>(), 8);
    }

    #[test]
    fn check_enclave_identity_header_layout() {
        // 1+3 (id) + 4 (version) + 8 (issue) + 8 (next_update) + 2 (tcb_eval) + 2 (isvprodid)
        // + 8 (misc) + 8 (misc_mask) + 32 (attr) + 32 (attr_mask) + 64 (mrsigner)
        // + 4 (levels_count) + 4 (levels_payload_len) + 4 (final_padding)
        // = 4+4+8+8+4+8+8+32+32+64+4+4+4 = 184
        assert_eq!(size_of::<EnclaveIdentityHeader>(), 184);
        assert_eq!(align_of::<EnclaveIdentityHeader>(), 8);
    }

    #[test]
    fn check_enclave_identity_pod_layout() {
        // 64 (sig) + 184 (header) = 248
        assert_eq!(size_of::<EnclaveIdentityPod>(), 248);
        assert_eq!(align_of::<EnclaveIdentityPod>(), 8);
    }
}
