// src/types/pod/tcb_info/zero_copy/iterators.rs

use super::error::ZeroCopyError;
use super::structs::{
    TcbComponentZeroCopy, TcbLevelZeroCopy, TdxModuleIdentityZeroCopy, TdxTcbLevelZeroCopy,
};
use crate::types::pod::tcb_info::{
    TcbComponentHeader, TcbLevelHeader, TdxModuleIdentityHeader, TdxTcbLevelHeader,
};
use bytemuck::Pod;
use core::str;

use core::mem; // For align_of

// Helper from structs.rs - consider moving to a shared util if this pattern repeats more
#[inline]
fn cast_slice<T: Pod>(slice: &[u8]) -> Result<&T, ZeroCopyError> {
    bytemuck::try_from_bytes(slice).map_err(ZeroCopyError::from_bytemuck_error)
}

// --- Iterators ---

// Iterator for Advisory IDs (string slices)
pub struct AdvisoryIdIter<'a> {
    lengths_payload: &'a [u8], // Slice containing array of u16 lengths
    data_payload: &'a [u8],    // Slice containing concatenated string data
    count: u32,
    current_idx: u32,
    current_data_offset: usize,
}

impl<'a> AdvisoryIdIter<'a> {
    pub(super) fn new(lengths_payload: &'a [u8], data_payload: &'a [u8], count: u32) -> Self {
        Self {
            lengths_payload,
            data_payload,
            count,
            current_idx: 0,
            current_data_offset: 0,
        }
    }
}

impl<'a> Iterator for AdvisoryIdIter<'a> {
    type Item = Result<&'a str, ZeroCopyError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_idx >= self.count {
            return None;
        }

        let len_size = core::mem::size_of::<u16>();
        let len_offset = (self.current_idx as usize).checked_mul(len_size)?;
        let len_bytes_end = len_offset.checked_add(len_size)?;

        if len_bytes_end > self.lengths_payload.len() {
            return Some(Err(ZeroCopyError::InvalidSliceLength));
        }

        let len_bytes_slice = self.lengths_payload.get(len_offset..len_bytes_end)?;
        let len = u16::from_le_bytes(len_bytes_slice.try_into().ok()?) as usize;

        let data_end = self.current_data_offset.checked_add(len)?;
        if data_end > self.data_payload.len() {
            return Some(Err(ZeroCopyError::InvalidSliceLength));
        }

        let data_slice = self.data_payload.get(self.current_data_offset..data_end)?;
        let res = str::from_utf8(data_slice).map_err(|_| ZeroCopyError::InvalidUtf8);

        self.current_data_offset = data_end;
        self.current_idx += 1;
        Some(res)
    }
}

// Iterator for TdxTcbLevelZeroCopy
pub struct TdxTcbLevelIter<'a> {
    full_payload: &'a [u8], // This is the payload for *all* TdxTcbLevels for a given identity
    count: u32,
    current_idx: u32,
    current_offset: usize,
}

impl<'a> TdxTcbLevelIter<'a> {
    pub(super) fn new(full_payload: &'a [u8], count: u32) -> Self {
        Self {
            full_payload,
            count,
            current_idx: 0,
            current_offset: 0,
        }
    }
}

impl<'a> Iterator for TdxTcbLevelIter<'a> {
    type Item = Result<TdxTcbLevelZeroCopy<'a>, ZeroCopyError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_idx >= self.count {
            return None;
        }

        let header_size = core::mem::size_of::<TdxTcbLevelHeader>();
        let header_end = self.current_offset.checked_add(header_size)?;
        if header_end > self.full_payload.len() {
            return Some(Err(ZeroCopyError::InvalidSliceLength));
        }

        let header_slice = &self.full_payload[self.current_offset..header_end];
        let header: &'a TdxTcbLevelHeader = match cast_slice(header_slice) {
            Ok(h) => h,
            Err(e) => return Some(Err(e)),
        };

        let current_item_internal_offset = header_end;

        let actual_item_payload_len = header
            .advisory_ids_lengths_array_len
            .checked_add(header.advisory_ids_data_total_len)
            .ok_or(ZeroCopyError::InvalidOffset);

        let actual_item_payload_len = match actual_item_payload_len {
            Ok(len) => len as usize,
            Err(e) => return Some(Err(e)),
        };

        let item_payload_actual_end =
            match current_item_internal_offset.checked_add(actual_item_payload_len) {
                Some(end) => end,
                None => return Some(Err(ZeroCopyError::InvalidOffset)),
            };

        if item_payload_actual_end > self.full_payload.len() {
            return Some(Err(ZeroCopyError::InvalidSliceLength));
        }

        let item_payload_slice =
            &self.full_payload[current_item_internal_offset..item_payload_actual_end];

        let view_result = TdxTcbLevelZeroCopy::new(header, item_payload_slice);

        self.current_offset = item_payload_actual_end; // End of actual data for this item

        // Align self.current_offset for the NEXT header
        let align_to = mem::align_of::<TdxTcbLevelHeader>();
        self.current_offset = (self.current_offset + align_to - 1) & !(align_to - 1);

        self.current_idx += 1;
        Some(view_result)
    }
}

// Iterator for TdxModuleIdentityZeroCopy
pub struct TdxModuleIdentityIter<'a> {
    full_payload: &'a [u8], // Payload for *all* TdxModuleIdentities for a TcbInfo
    count: u32,
    current_idx: u32,
    current_offset: usize,
}

impl<'a> TdxModuleIdentityIter<'a> {
    pub(super) fn new(full_payload: &'a [u8], count: u32) -> Self {
        Self {
            full_payload,
            count,
            current_idx: 0,
            current_offset: 0,
        }
    }
}

impl<'a> Iterator for TdxModuleIdentityIter<'a> {
    type Item = Result<TdxModuleIdentityZeroCopy<'a>, ZeroCopyError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_idx >= self.count {
            return None;
        }
        let header_size = core::mem::size_of::<TdxModuleIdentityHeader>();
        let header_end = self.current_offset.checked_add(header_size)?;
        if header_end > self.full_payload.len() {
            return Some(Err(ZeroCopyError::InvalidSliceLength));
        }

        let header_slice = &self.full_payload[self.current_offset..header_end];
        let header: &'a TdxModuleIdentityHeader = match cast_slice(header_slice) {
            Ok(h) => h,
            Err(e) => return Some(Err(e)),
        };

        let current_item_internal_offset = header_end;

        let alignment = mem::align_of::<TdxTcbLevelHeader>();
        let offset = (header.id_len as usize + (alignment - 1)) & !(alignment - 1);
        let actual_item_payload_len = (offset)
            .checked_add(header.tcb_levels_total_payload_len as usize)
            .ok_or(ZeroCopyError::InvalidOffset);

        let actual_item_payload_len = match actual_item_payload_len {
            Ok(len) => len,
            Err(e) => return Some(Err(e)),
        };

        let item_payload_actual_end =
            match current_item_internal_offset.checked_add(actual_item_payload_len) {
                Some(end) => end,
                None => return Some(Err(ZeroCopyError::InvalidOffset)),
            };
        if item_payload_actual_end > self.full_payload.len() {
            return Some(Err(ZeroCopyError::InvalidSliceLength));
        }
        let item_payload_slice =
            &self.full_payload[current_item_internal_offset..item_payload_actual_end];

        let view_result = TdxModuleIdentityZeroCopy::new(header, item_payload_slice);

        self.current_offset = item_payload_actual_end; // End of actual data for this item

        // Align self.current_offset for the NEXT header
        let align_to = mem::align_of::<TdxModuleIdentityHeader>();
        self.current_offset = (self.current_offset + align_to - 1) & !(align_to - 1);

        self.current_idx += 1;
        Some(view_result)
    }
}

// Iterator for TcbComponentZeroCopy
pub struct TcbComponentIter<'a> {
    component_headers: &'a [TcbComponentHeader; 16], // Array of headers
    full_strings_payload: &'a [u8],                  // Concatenated strings for all 16 components
    current_idx: usize,                              // Index into the headers array (0-15)
    current_string_offset: usize,                    // Offset into full_strings_payload
}

impl<'a> TcbComponentIter<'a> {
    pub(super) fn new(
        headers: &'a [TcbComponentHeader; 16],
        full_strings_payload: &'a [u8],
    ) -> Self {
        Self {
            component_headers: headers,
            full_strings_payload,
            current_idx: 0,
            current_string_offset: 0,
        }
    }
}

impl<'a> Iterator for TcbComponentIter<'a> {
    type Item = Result<TcbComponentZeroCopy<'a>, ZeroCopyError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_idx >= 16 {
            return None;
        }
        let header = &self.component_headers[self.current_idx];
        let cat_len = header.category_len as usize;
        let comp_type_len = header.component_type_len as usize;
        let total_len_for_comp = cat_len.checked_add(comp_type_len)?;

        let string_data_end = self.current_string_offset.checked_add(total_len_for_comp)?;
        if string_data_end > self.full_strings_payload.len() {
            return Some(Err(ZeroCopyError::InvalidSliceLength));
        }

        let component_string_slice = self
            .full_strings_payload
            .get(self.current_string_offset..string_data_end)?;

        let view_res = TcbComponentZeroCopy::new(header, component_string_slice);

        self.current_string_offset = string_data_end;
        self.current_idx += 1;
        Some(view_res)
    }
}

// Iterator for TcbLevelZeroCopy
pub struct TcbLevelIter<'a> {
    full_payload: &'a [u8], // Payload for *all* TcbLevels for a TcbInfo
    count: u32,
    current_idx: u32,
    current_offset: usize,
}

impl<'a> TcbLevelIter<'a> {
    pub(super) fn new(full_payload: &'a [u8], count: u32) -> Self {
        Self {
            full_payload,
            count,
            current_idx: 0,
            current_offset: 0,
        }
    }
}

impl<'a> Iterator for TcbLevelIter<'a> {
    type Item = Result<TcbLevelZeroCopy<'a>, ZeroCopyError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_idx >= self.count {
            return None;
        }

        let header_size = mem::size_of::<TcbLevelHeader>();
        let header_slice_end = match self.current_offset.checked_add(header_size) {
            Some(end) => end,
            None => return Some(Err(ZeroCopyError::InvalidOffset)),
        };

        if header_slice_end > self.full_payload.len() {
            return Some(Err(ZeroCopyError::InvalidSliceLength));
        }

        let header_slice = &self.full_payload[self.current_offset..header_slice_end];
        let header: &'a TcbLevelHeader = match cast_slice(header_slice) {
            Ok(h) => h,
            Err(e) => return Some(Err(e)),
        };

        let current_item_internal_offset = header_slice_end;

        let sgx_strings_len = header.sgx_components_strings_total_len as usize;
        let tdx_strings_len = if header.tdx_tcb_components_present == 1 {
            header.tdx_components_strings_total_len as usize
        } else {
            0
        };
        let adv_ids_lengths_len = header.advisory_ids_lengths_array_len as usize;
        let adv_ids_data_len = header.advisory_ids_data_total_len as usize;

        let actual_item_payload_len = sgx_strings_len
            .checked_add(tdx_strings_len)
            .and_then(|sum| sum.checked_add(adv_ids_lengths_len))
            .and_then(|sum| sum.checked_add(adv_ids_data_len));

        let actual_item_payload_len = match actual_item_payload_len {
            Some(len) => len,
            None => return Some(Err(ZeroCopyError::InvalidOffset)),
        };

        let item_payload_actual_end =
            match current_item_internal_offset.checked_add(actual_item_payload_len) {
                Some(end) => end,
                None => return Some(Err(ZeroCopyError::InvalidOffset)),
            };

        if item_payload_actual_end > self.full_payload.len() {
            return Some(Err(ZeroCopyError::InvalidSliceLength));
        }
        let item_payload_slice =
            &self.full_payload[current_item_internal_offset..item_payload_actual_end];

        let view_result = TcbLevelZeroCopy::new(header, item_payload_slice);

        self.current_offset = item_payload_actual_end; // End of actual data for this item

        // Align self.current_offset for the NEXT header
        let align_to = mem::align_of::<TcbLevelHeader>();
        self.current_offset = (self.current_offset + align_to - 1) & !(align_to - 1);

        self.current_idx += 1;
        Some(view_result)
    }
}
