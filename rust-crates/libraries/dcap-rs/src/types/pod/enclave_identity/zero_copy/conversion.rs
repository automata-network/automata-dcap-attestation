// src/types/pod/enclave_identity/zero_copy/conversion.rs

use super::error::ZeroCopyError;
use super::structs::{EnclaveIdentityZeroCopy, QeTcbLevelZeroCopy};
use crate::types::enclave_identity::{
    EnclaveIdentity, EnclaveType, QeTcb, QeTcbLevel, QeTcbStatus,
};
use chrono::{TimeZone, Utc};

// Helper to convert fixed-size byte arrays (representing ASCII hex or plain strings)
// from ZeroCopy structs back to owned Strings. Stops at first null byte or end of array.
fn zero_copy_bytes_to_string(bytes: &[u8]) -> String {
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..len]).into_owned()
}

// Helper to convert u8 back to EnclaveType
fn enclave_type_from_byte(byte: u8) -> Result<EnclaveType, ZeroCopyError> {
    match byte {
        0 => Ok(EnclaveType::Qe),
        1 => Ok(EnclaveType::Qve),
        2 => Ok(EnclaveType::TdQe),
        _ => Err(ZeroCopyError::InvalidEnumValue),
    }
}

// Helper to convert u8 back to QeTcbStatus
fn qe_tcb_status_from_byte(byte: u8) -> Result<QeTcbStatus, ZeroCopyError> {
    match byte {
        0 => Ok(QeTcbStatus::UpToDate),
        1 => Ok(QeTcbStatus::SWHardeningNeeded),
        2 => Ok(QeTcbStatus::OutOfDate),
        3 => Ok(QeTcbStatus::OutOfDateConfigurationNeeded),
        4 => Ok(QeTcbStatus::ConfigurationNeeded),
        5 => Ok(QeTcbStatus::ConfigurationAndSWHardeningNeeded),
        6 => Ok(QeTcbStatus::Revoked),
        7 => Ok(QeTcbStatus::Unspecified),
        _ => Err(ZeroCopyError::InvalidEnumValue),
    }
}

pub fn qe_tcb_level_from_zero_copy(view: &QeTcbLevelZeroCopy) -> Result<QeTcbLevel, ZeroCopyError> {
    let mut advisory_ids_vec = Vec::new();
    if view.advisory_ids_count() > 0 {
        for adv_id_res in view.advisory_ids() {
            advisory_ids_vec.push(adv_id_res?.to_string());
        }
    }

    Ok(QeTcbLevel {
        tcb: QeTcb {
            isvsvn: view.isvsvn(),
        },
        tcb_date: Utc
            .timestamp_opt(view.tcb_date_timestamp(), 0)
            .single()
            .ok_or(ZeroCopyError::InvalidOffset)?, // Using InvalidOffset for timestamp errors
        tcb_status: qe_tcb_status_from_byte(view.tcb_status_byte())?,
        advisory_ids: if advisory_ids_vec.is_empty() {
            None
        } else {
            Some(advisory_ids_vec)
        },
    })
}

pub fn enclave_identity_from_zero_copy(
    view: &EnclaveIdentityZeroCopy,
) -> Result<EnclaveIdentity, ZeroCopyError> {
    let mut tcb_levels_vec = Vec::new();
    if view.tcb_levels_count() > 0 {
        for tcb_level_view_res in view.tcb_levels() {
            let tcb_level_view = tcb_level_view_res?;
            tcb_levels_vec.push(qe_tcb_level_from_zero_copy(&tcb_level_view)?);
        }
    }

    Ok(EnclaveIdentity {
        id: enclave_type_from_byte(view.id_byte())?,
        version: view.version(),
        issue_date: Utc
            .timestamp_opt(view.issue_date_timestamp(), 0)
            .single()
            .ok_or(ZeroCopyError::InvalidOffset)?,
        next_update: Utc
            .timestamp_opt(view.next_update_timestamp(), 0)
            .single()
            .ok_or(ZeroCopyError::InvalidOffset)?,
        tcb_evaluation_data_number: view.tcb_evaluation_data_number(),
        miscselect: zero_copy_bytes_to_string(&view.header.miscselect_hex),
        miscselect_mask: zero_copy_bytes_to_string(&view.header.miscselect_mask_hex),
        attributes: zero_copy_bytes_to_string(&view.header.attributes_hex),
        attributes_mask: zero_copy_bytes_to_string(&view.header.attributes_mask_hex),
        mrsigner: zero_copy_bytes_to_string(&view.header.mrsigner_hex),
        isvprodid: view.isvprodid(),
        tcb_levels: tcb_levels_vec,
    })
}
