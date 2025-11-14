// src/types/pod/enclave_identity/zero_copy/iterators.rs

use super::error::ZeroCopyError;
use super::structs::QeTcbLevelZeroCopy;
use crate::types::pod::enclave_identity::QeTcbLevelPodHeader;
use bytemuck::Pod;
use core::{mem, str};

// Helper from structs.rs - consider moving to a shared util
#[inline]
fn cast_slice<T: Pod>(slice: &[u8]) -> Result<&T, ZeroCopyError> {
    bytemuck::try_from_bytes(slice).map_err(ZeroCopyError::from_bytemuck_error)
}

// --- Iterators ---

// Iterator for Advisory IDs (string slices)
// This can be identical to the one in TcbInfo if no specific changes are needed.
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
            // Not enough data in lengths_payload for this index
            self.current_idx = self.count; // Exhaust iterator
            return Some(Err(ZeroCopyError::InvalidSliceLength));
        }

        let len_bytes_slice = self.lengths_payload.get(len_offset..len_bytes_end)?;
        let len = u16::from_le_bytes(match len_bytes_slice.try_into() {
            Ok(arr) => arr,
            Err(_) => {
                // Should not happen if previous check passed
                self.current_idx = self.count;
                return Some(Err(ZeroCopyError::InvalidSliceLength));
            },
        }) as usize;

        let data_end = self.current_data_offset.checked_add(len)?;
        if data_end > self.data_payload.len() {
            // Not enough data in data_payload for this string
            self.current_idx = self.count; // Exhaust iterator
            return Some(Err(ZeroCopyError::InvalidSliceLength));
        }

        let data_slice = self.data_payload.get(self.current_data_offset..data_end)?;
        let res = str::from_utf8(data_slice).map_err(|_| ZeroCopyError::InvalidUtf8);

        self.current_data_offset = data_end;
        self.current_idx += 1;
        Some(res)
    }
}

// Iterator for QeTcbLevelZeroCopy
pub struct QeTcbLevelIter<'a> {
    full_payload: &'a [u8], // This is the payload for *all* QeTcbLevels
    count: u32,
    current_idx: u32,
    current_offset: usize,
}

impl<'a> QeTcbLevelIter<'a> {
    pub(super) fn new(full_payload: &'a [u8], count: u32) -> Self {
        Self {
            full_payload,
            count,
            current_idx: 0,
            current_offset: 0,
        }
    }
}

impl<'a> Iterator for QeTcbLevelIter<'a> {
    type Item = Result<QeTcbLevelZeroCopy<'a>, ZeroCopyError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_idx >= self.count {
            return None;
        }

        let header_size = mem::size_of::<QeTcbLevelPodHeader>();
        let header_slice_end = match self.current_offset.checked_add(header_size) {
            Some(end) => end,
            None => {
                // Offset calculation overflow
                self.current_idx = self.count;
                return Some(Err(ZeroCopyError::InvalidOffset));
            },
        };

        if header_slice_end > self.full_payload.len() {
            self.current_idx = self.count;
            return Some(Err(ZeroCopyError::InvalidSliceLength));
        }

        let header_slice = &self.full_payload[self.current_offset..header_slice_end];
        let header: &'a QeTcbLevelPodHeader = match cast_slice(header_slice) {
            Ok(h) => h,
            Err(e) => {
                self.current_idx = self.count;
                return Some(Err(e));
            },
        };

        let current_item_internal_payload_start = header_slice_end;

        let adv_ids_lengths_len = header.advisory_ids_lengths_array_len as usize;
        let adv_ids_data_len = header.advisory_ids_data_total_len as usize;

        let actual_item_payload_len = match adv_ids_lengths_len.checked_add(adv_ids_data_len) {
            Some(len) => len,
            None => {
                // Offset calculation overflow
                self.current_idx = self.count;
                return Some(Err(ZeroCopyError::InvalidOffset));
            },
        };

        let item_payload_actual_end =
            match current_item_internal_payload_start.checked_add(actual_item_payload_len) {
                Some(end) => end,
                None => {
                    // Offset calculation overflow
                    self.current_idx = self.count;
                    return Some(Err(ZeroCopyError::InvalidOffset));
                },
            };

        if item_payload_actual_end > self.full_payload.len() {
            self.current_idx = self.count;
            return Some(Err(ZeroCopyError::InvalidSliceLength));
        }
        let item_payload_slice =
            &self.full_payload[current_item_internal_payload_start..item_payload_actual_end];

        let view_result = QeTcbLevelZeroCopy::new(header, item_payload_slice);

        self.current_offset = item_payload_actual_end; // End of actual data for this item

        // Align self.current_offset for the NEXT header
        let align_to = mem::align_of::<QeTcbLevelPodHeader>(); // Align to 8
        self.current_offset = (self.current_offset + align_to - 1) & !(align_to - 1);

        self.current_idx += 1;
        Some(view_result)
    }
}
