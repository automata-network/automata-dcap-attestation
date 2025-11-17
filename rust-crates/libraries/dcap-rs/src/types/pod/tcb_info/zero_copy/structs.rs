// src/types/pod/tcb_info/zero_copy/structs.rs

use super::error::ZeroCopyError;
use super::iterators::*; // Will define iterators later
use crate::types::pod::tcb_info::{
    TcbComponentHeader, TcbInfoHeader, TcbLevelHeader, TdxModuleIdentityHeader, TdxModulePodData,
    TdxTcbLevelHeader,
};
use bytemuck::Pod;
use std::str::from_utf8;

// --- Helper to cast slices ---
// It's good practice to have this in a shared utility if used in multiple places,
// but for now, keeping it here for self-containment of this module's direct needs.
#[inline]
fn cast_slice<T: Pod>(slice: &[u8]) -> Result<&T, ZeroCopyError> {
    bytemuck::try_from_bytes(slice).map_err(ZeroCopyError::from_bytemuck_error)
}

// --- Top-Level ZeroCopy Struct ---

#[derive(Debug, Copy, Clone)]
pub struct TcbInfoZeroCopy<'a> {
    pub header: &'a TcbInfoHeader,
    tdx_module_data_payload: Option<&'a TdxModulePodData>, // Directly borrowed if present
    tdx_module_identities_section_payload: &'a [u8],
    tcb_levels_section_payload: &'a [u8],
}

impl<'a> TcbInfoZeroCopy<'a> {
    /// Creates a zero-copy view from a byte slice that starts with TcbInfoHeader
    /// and is followed by its complete payload.
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ZeroCopyError> {
        if bytes.len() < core::mem::size_of::<TcbInfoHeader>() {
            return Err(ZeroCopyError::InvalidSliceLength);
        }
        let (header_bytes, main_payload) = bytes.split_at(core::mem::size_of::<TcbInfoHeader>());
        let header: &TcbInfoHeader = cast_slice(header_bytes)?;

        let mut current_offset = 0;
        let tdx_module_data_payload = if header.tdx_module_present == 1 {
            let len = header.tdx_module_data_len as usize;
            let slice = main_payload
                .get(current_offset..current_offset + len)
                .ok_or(ZeroCopyError::InvalidSliceLength)?;
            current_offset += len;
            Some(cast_slice(slice)?)
        } else {
            None
        };

        let identities_len = header.tdx_module_identities_total_payload_len as usize;
        let tdx_module_identities_section_payload = main_payload
            .get(current_offset..current_offset + identities_len)
            .ok_or(ZeroCopyError::InvalidSliceLength)?;
        current_offset += identities_len;

        let levels_len = header.tcb_levels_total_payload_len as usize;
        let tcb_levels_section_payload = main_payload
            .get(current_offset..current_offset + levels_len)
            .ok_or(ZeroCopyError::InvalidSliceLength)?;
        current_offset += levels_len;

        if current_offset > main_payload.len() {
            return Err(ZeroCopyError::InvalidSliceLength);
        }

        Ok(Self {
            header,
            tdx_module_data_payload,
            tdx_module_identities_section_payload,
            tcb_levels_section_payload,
        })
    }

    // --- Direct Header Accessors ---
    pub fn id_type_bytes(&self) -> &'a [u8; 6] {
        &self.header.id_type
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
    // Parses the hex string and returns the byte array
    pub fn fmspc(&self) -> [u8; 6] {
        hex::decode(from_utf8(&self.header.fmspc_hex).unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    }
    // Parses the hex string and returns the byte array
    pub fn pce_id(&self) -> [u8; 2] {
        hex::decode(from_utf8(&self.header.pce_id_hex).unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    }
    pub fn tcb_type(&self) -> u8 {
        self.header.tcb_type
    }
    pub fn tcb_evaluation_data_number(&self) -> u32 {
        self.header.tcb_evaluation_data_number
    }

    // --- Parsed/Structured Accessors ---
    pub fn tdx_module(&self) -> Option<TdxModulePodDataZeroCopy<'a>> {
        self.tdx_module_data_payload
            .map(TdxModulePodDataZeroCopy::new)
    }

    pub fn tdx_module_identities_count(&self) -> u32 {
        self.header.tdx_module_identities_count
    }
    pub fn tdx_module_identities(&self) -> TdxModuleIdentityIter<'a> {
        TdxModuleIdentityIter::new(
            self.tdx_module_identities_section_payload,
            self.header.tdx_module_identities_count,
        )
    }

    pub fn tcb_levels_count(&self) -> u32 {
        self.header.tcb_levels_count
    }
    pub fn tcb_levels(&self) -> TcbLevelIter<'a> {
        TcbLevelIter::new(
            self.tcb_levels_section_payload,
            self.header.tcb_levels_count,
        )
    }
}

// --- Individual Component ZeroCopy Structs ---

// TdxModulePodDataZeroCopy (simple wrapper for already Pod data)
#[derive(Debug, Copy, Clone)]
pub struct TdxModulePodDataZeroCopy<'a> {
    pub data: &'a TdxModulePodData,
}
impl<'a> TdxModulePodDataZeroCopy<'a> {
    pub fn new(data: &'a TdxModulePodData) -> Self {
        Self { data }
    }
    pub fn mrsigner(&self) -> [u8; 48] {
        hex::decode(from_utf8(&self.data.mrsigner_hex).unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    }
    pub fn attributes(&self) -> [u8; 8] {
        hex::decode(from_utf8(&self.data.attributes_hex).unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    }
    pub fn attributes_mask(&self) -> [u8; 8] {
        hex::decode(from_utf8(&self.data.attributes_mask_hex).unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    }
}

// TcbComponentZeroCopy
#[derive(Debug, Copy, Clone)]
pub struct TcbComponentZeroCopy<'a> {
    pub header: &'a TcbComponentHeader,
    category_payload: &'a [u8],
    component_type_payload: &'a [u8],
}

impl<'a> TcbComponentZeroCopy<'a> {
    // 'payload' is the combined string data for THIS component
    pub fn new(header: &'a TcbComponentHeader, payload: &'a [u8]) -> Result<Self, ZeroCopyError> {
        let cat_len = header.category_len as usize;
        let comp_type_len = header.component_type_len as usize;
        if cat_len
            .checked_add(comp_type_len)
            .ok_or(ZeroCopyError::InvalidOffset)?
            > payload.len()
        {
            return Err(ZeroCopyError::InvalidSliceLength);
        }
        Ok(Self {
            header,
            category_payload: &payload[..cat_len],
            component_type_payload: &payload[cat_len..cat_len + comp_type_len],
        })
    }
    pub fn cpusvn(&self) -> u8 {
        self.header.cpusvn
    }
    pub fn category_str(&self) -> Result<&'a str, ZeroCopyError> {
        from_utf8(self.category_payload).map_err(|_| ZeroCopyError::InvalidUtf8)
    }
    pub fn component_type_str(&self) -> Result<&'a str, ZeroCopyError> {
        from_utf8(self.component_type_payload).map_err(|_| ZeroCopyError::InvalidUtf8)
    }
}

// TdxTcbLevelZeroCopy
#[derive(Debug, Copy, Clone)]
pub struct TdxTcbLevelZeroCopy<'a> {
    header: &'a TdxTcbLevelHeader,
    advisory_ids_lengths_payload: &'a [u8],
    advisory_ids_data_payload: &'a [u8],
}

impl<'a> TdxTcbLevelZeroCopy<'a> {
    // 'payload' is specific to this TdxTcbLevel's advisory IDs (lengths array + data)
    pub fn new(header: &'a TdxTcbLevelHeader, payload: &'a [u8]) -> Result<Self, ZeroCopyError> {
        let lengths_len = header.advisory_ids_lengths_array_len as usize;
        let data_len = header.advisory_ids_data_total_len as usize;
        if lengths_len
            .checked_add(data_len)
            .ok_or(ZeroCopyError::InvalidOffset)?
            > payload.len()
        {
            return Err(ZeroCopyError::InvalidSliceLength);
        }
        Ok(Self {
            header,
            advisory_ids_lengths_payload: &payload[..lengths_len],
            advisory_ids_data_payload: &payload[lengths_len..lengths_len + data_len],
        })
    }
    pub fn tcb_isvsvn(&self) -> u8 {
        self.header.tcb_isvsvn
    }
    pub fn tcb_status(&self) -> u8 {
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

// TdxModuleIdentityZeroCopy
#[derive(Debug, Copy, Clone)]
pub struct TdxModuleIdentityZeroCopy<'a> {
    pub header: &'a TdxModuleIdentityHeader,
    id_payload: &'a [u8],                 // Slice for the ID string
    tcb_levels_section_payload: &'a [u8], // Slice for all TdxTcbLevels of this identity
}

impl<'a> TdxModuleIdentityZeroCopy<'a> {
    // 'payload' is specific to this TdxModuleIdentity (id_string + its TdxTcbLevels section)
    pub fn new(
        header: &'a TdxModuleIdentityHeader,
        payload: &'a [u8],
    ) -> Result<Self, ZeroCopyError> {
        let id_len = header.id_len as usize;

        let tcb_levels_len = header.tcb_levels_total_payload_len as usize;

        let tcb_levels_alignment = core::mem::align_of::<TdxTcbLevelHeader>();
        let offset = (id_len + (tcb_levels_alignment - 1)) & !(tcb_levels_alignment - 1);

        if offset
            .checked_add(tcb_levels_len)
            .ok_or(ZeroCopyError::InvalidOffset)?
            > payload.len()
        {
            return Err(ZeroCopyError::InvalidSliceLength);
        }

        Ok(Self {
            header,
            id_payload: &payload[..id_len],
            tcb_levels_section_payload: &payload[offset..offset + tcb_levels_len],
        })
    }
    pub fn mrsigner(&self) -> [u8; 48] {
        hex::decode(from_utf8(&self.header.mrsigner_hex).unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    }
    pub fn attributes(&self) -> [u8; 8] {
        hex::decode(from_utf8(&self.header.attributes_hex).unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    }
    pub fn attributes_mask(&self) -> [u8; 8] {
        hex::decode(from_utf8(&self.header.attributes_mask_hex).unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    }
    pub fn id_str(&self) -> Result<&'a str, ZeroCopyError> {
        from_utf8(self.id_payload).map_err(|_| ZeroCopyError::InvalidUtf8)
    }
    pub fn tcb_levels_count(&self) -> u32 {
        self.header.tcb_levels_count
    }
    pub fn tcb_levels(&self) -> TdxTcbLevelIter<'a> {
        TdxTcbLevelIter::new(
            self.tcb_levels_section_payload,
            self.header.tcb_levels_count,
        )
    }
}

// TcbLevelZeroCopy
#[derive(Debug, Copy, Clone)]
pub struct TcbLevelZeroCopy<'a> {
    pub header: &'a TcbLevelHeader,
    sgx_components_strings_payload: &'a [u8],
    tdx_components_strings_payload: Option<&'a [u8]>,
    advisory_ids_lengths_payload: &'a [u8],
    advisory_ids_data_payload: &'a [u8],
}

impl<'a> TcbLevelZeroCopy<'a> {
    // 'payload' is specific to this TcbLevel (sgx_comp_strings | tdx_comp_strings (opt) | adv_id_lengths | adv_id_data)
    pub fn new(header: &'a TcbLevelHeader, payload: &'a [u8]) -> Result<Self, ZeroCopyError> {
        let mut current_offset = 0;

        let sgx_len = header.sgx_components_strings_total_len as usize;
        let sgx_payload = payload
            .get(current_offset..current_offset + sgx_len)
            .ok_or(ZeroCopyError::InvalidSliceLength)?;
        current_offset += sgx_len;

        let tdx_payload = if header.tdx_tcb_components_present == 1 {
            let tdx_len = header.tdx_components_strings_total_len as usize;
            let slice = payload
                .get(current_offset..current_offset + tdx_len)
                .ok_or(ZeroCopyError::InvalidSliceLength)?;
            current_offset += tdx_len;
            Some(slice)
        } else {
            None
        };

        let adv_lengths_len = header.advisory_ids_lengths_array_len as usize;
        let adv_lengths_payload = payload
            .get(current_offset..current_offset + adv_lengths_len)
            .ok_or(ZeroCopyError::InvalidSliceLength)?;
        current_offset += adv_lengths_len;

        let adv_data_len = header.advisory_ids_data_total_len as usize;
        let adv_data_payload = payload
            .get(current_offset..current_offset + adv_data_len)
            .ok_or(ZeroCopyError::InvalidSliceLength)?;
        current_offset += adv_data_len;

        if current_offset > payload.len() {
            return Err(ZeroCopyError::InvalidSliceLength);
        }

        Ok(Self {
            header,
            sgx_components_strings_payload: sgx_payload,
            tdx_components_strings_payload: tdx_payload,
            advisory_ids_lengths_payload: adv_lengths_payload,
            advisory_ids_data_payload: adv_data_payload,
        })
    }
    pub fn tcb_status(&self) -> u8 {
        self.header.tcb_status
    }
    pub fn pce_svn(&self) -> u16 {
        self.header.pce_svn
    }
    pub fn tcb_date_timestamp(&self) -> i64 {
        self.header.tcb_date_timestamp
    }
    pub fn sgx_tcb_components(&self) -> TcbComponentIter<'a> {
        TcbComponentIter::new(
            &self.header.sgx_tcb_components,
            self.sgx_components_strings_payload,
        )
    }
    pub fn tdx_tcb_components(&self) -> Option<TcbComponentIter<'a>> {
        if self.header.tdx_tcb_components_present == 1 {
            self.tdx_components_strings_payload
                .map(|payload| TcbComponentIter::new(&self.header.tdx_tcb_components, payload))
        } else {
            None
        }
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
