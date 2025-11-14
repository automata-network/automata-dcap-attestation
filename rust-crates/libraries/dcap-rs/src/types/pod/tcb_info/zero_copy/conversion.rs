// src/types/pod/tcb_info/zero_copy/conversion.rs

use super::error::ZeroCopyError;
use super::structs::*;
use crate::types::tcb_info::{
    Tcb, TcbComponentV3, TcbInfo, TcbInfoVersion, TcbLevel, TcbStatus, TcbTdx, TdxModule,
    TdxModuleIdentity, TdxTcbLevel,
};
use chrono::{TimeZone, Utc};

// Helper to convert fixed-size byte arrays (representing ASCII hex or plain strings)
// from ZeroCopy structs back to owned Strings. Stops at first null byte or end of array.
fn zero_copy_bytes_to_string(bytes: &[u8]) -> String {
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..len]).into_owned()
}

// Helper to create an empty TcbComponentV3 for array initialization
fn empty_tcb_component_v3() -> TcbComponentV3 {
    TcbComponentV3 {
        svn: 0,
        category: None,
        component_type: None,
    }
}

pub fn tcb_info_from_zero_copy(view: &TcbInfoZeroCopy) -> Result<TcbInfo, ZeroCopyError> {
    let id_str = zero_copy_bytes_to_string(view.id_type_bytes());
    let id_option = if id_str.is_empty() {
        None
    } else {
        Some(id_str)
    };

    let version =
        TcbInfoVersion::try_from(view.version()).map_err(|_| ZeroCopyError::InvalidEnumValue)?;

    let issue_date = Utc
        .timestamp_opt(view.issue_date_timestamp(), 0)
        .single()
        .ok_or(ZeroCopyError::InvalidOffset)?;
    let next_update = Utc
        .timestamp_opt(view.next_update_timestamp(), 0)
        .single()
        .ok_or(ZeroCopyError::InvalidOffset)?;

    let fmspc = zero_copy_bytes_to_string(&view.header.fmspc_hex);
    let pce_id = zero_copy_bytes_to_string(&view.header.pce_id_hex);

    let tdx_module: Option<TdxModule> = view.tdx_module().map(|tdx_mod_view| TdxModule {
        mrsigner: zero_copy_bytes_to_string(&tdx_mod_view.data.mrsigner_hex),
        attributes: zero_copy_bytes_to_string(&tdx_mod_view.data.attributes_hex),
        attributes_mask: zero_copy_bytes_to_string(&tdx_mod_view.data.attributes_mask_hex),
    });

    let mut tdx_module_identities_vec = Vec::new();
    if view.tdx_module_identities_count() > 0 {
        for identity_view_res in view.tdx_module_identities() {
            let identity_view = identity_view_res?;
            let mut tdx_tcb_levels_for_identity_vec = Vec::new();
            if identity_view.tcb_levels_count() > 0 {
                for tdx_tcb_level_view_res in identity_view.tcb_levels() {
                    let tdx_tcb_level_view = tdx_tcb_level_view_res?;
                    let mut advisory_ids_vec = Vec::new();
                    if tdx_tcb_level_view.advisory_ids_count() > 0 {
                        for adv_id_res in tdx_tcb_level_view.advisory_ids() {
                            advisory_ids_vec.push(adv_id_res?.to_string());
                        }
                    }
                    let tdx_tcb_level_app = TdxTcbLevel {
                        tcb: TcbTdx {
                            isvsvn: tdx_tcb_level_view.tcb_isvsvn(),
                        },
                        tcb_date: Utc
                            .timestamp_opt(tdx_tcb_level_view.tcb_date_timestamp(), 0)
                            .single()
                            .ok_or(ZeroCopyError::InvalidOffset)?,
                        tcb_status: TcbStatus::try_from(tdx_tcb_level_view.tcb_status())
                            .map_err(|_| ZeroCopyError::InvalidEnumValue)?,
                        advisory_ids: if advisory_ids_vec.is_empty() {
                            None
                        } else {
                            Some(advisory_ids_vec)
                        },
                    };
                    tdx_tcb_levels_for_identity_vec.push(tdx_tcb_level_app);
                }
            }
            let identity_app = TdxModuleIdentity {
                id: identity_view.id_str()?.to_string(),
                mrsigner: zero_copy_bytes_to_string(&identity_view.header.mrsigner_hex),
                attributes: zero_copy_bytes_to_string(&identity_view.header.attributes_hex),
                attributes_mask: zero_copy_bytes_to_string(
                    &identity_view.header.attributes_mask_hex,
                ),
                tcb_levels: tdx_tcb_levels_for_identity_vec,
            };
            tdx_module_identities_vec.push(identity_app);
        }
    }
    let tdx_module_identities_option = if tdx_module_identities_vec.is_empty() {
        None
    } else {
        Some(tdx_module_identities_vec)
    };

    let mut tcb_levels_vec = Vec::new();
    if view.tcb_levels_count() > 0 {
        for tcb_level_view_res in view.tcb_levels() {
            let tcb_level_view = tcb_level_view_res?;

            let mut sgx_components_app = core::array::from_fn(|_| empty_tcb_component_v3());
            for (i, comp_view_res) in tcb_level_view.sgx_tcb_components().enumerate() {
                let comp_view = comp_view_res?;
                sgx_components_app[i] = TcbComponentV3 {
                    svn: comp_view.cpusvn(),
                    category: Some(comp_view.category_str()?.to_string()).filter(|s| !s.is_empty()),
                    component_type: Some(comp_view.component_type_str()?.to_string())
                        .filter(|s| !s.is_empty()),
                };
            }

            let mut tdx_components_app_option: Option<[TcbComponentV3; 16]> = None;
            if let Some(tdx_comp_iter) = tcb_level_view.tdx_tcb_components() {
                let mut tdx_components_app_arr = core::array::from_fn(|_| empty_tcb_component_v3());
                for (i, comp_view_res) in tdx_comp_iter.enumerate() {
                    let comp_view = comp_view_res?;
                    tdx_components_app_arr[i] = TcbComponentV3 {
                        svn: comp_view.cpusvn(),
                        category: Some(comp_view.category_str()?.to_string())
                            .filter(|s| !s.is_empty()),
                        component_type: Some(comp_view.component_type_str()?.to_string())
                            .filter(|s| !s.is_empty()),
                    };
                }
                tdx_components_app_option = Some(tdx_components_app_arr);
            }

            let tcb_app = match version {
                TcbInfoVersion::V3 => Tcb::V3(Box::new(crate::types::tcb_info::TcbV3 {
                    sgxtcbcomponents: sgx_components_app,
                    pcesvn: tcb_level_view.pce_svn(),
                    tdxtcbcomponents: tdx_components_app_option,
                })),
                TcbInfoVersion::V2 => {
                    let mut sgx_svns = [0u8; 16];
                    for i in 0..16 {
                        sgx_svns[i] = sgx_components_app[i].svn;
                    }
                    Tcb::V2(crate::types::tcb_info::TcbV2 {
                        sgxtcbcomp01svn: sgx_svns[0],
                        sgxtcbcomp02svn: sgx_svns[1],
                        sgxtcbcomp03svn: sgx_svns[2],
                        sgxtcbcomp04svn: sgx_svns[3],
                        sgxtcbcomp05svn: sgx_svns[4],
                        sgxtcbcomp06svn: sgx_svns[5],
                        sgxtcbcomp07svn: sgx_svns[6],
                        sgxtcbcomp08svn: sgx_svns[7],
                        sgxtcbcomp09svn: sgx_svns[8],
                        sgxtcbcomp10svn: sgx_svns[9],
                        sgxtcbcomp11svn: sgx_svns[10],
                        sgxtcbcomp12svn: sgx_svns[11],
                        sgxtcbcomp13svn: sgx_svns[12],
                        sgxtcbcomp14svn: sgx_svns[13],
                        sgxtcbcomp15svn: sgx_svns[14],
                        sgxtcbcomp16svn: sgx_svns[15],
                        pcesvn: tcb_level_view.pce_svn(),
                    })
                },
            };

            let mut advisory_ids_vec = Vec::new();
            for adv_id_res in tcb_level_view.advisory_ids() {
                advisory_ids_vec.push(adv_id_res?.to_string());
            }

            let tcb_level_app = TcbLevel {
                tcb: tcb_app,
                tcb_date: Utc
                    .timestamp_opt(tcb_level_view.tcb_date_timestamp(), 0)
                    .single()
                    .ok_or(ZeroCopyError::InvalidOffset)?,
                tcb_status: TcbStatus::try_from(tcb_level_view.tcb_status())
                    .map_err(|_| ZeroCopyError::InvalidEnumValue)?,
                advisory_ids: if advisory_ids_vec.is_empty() {
                    None
                } else {
                    Some(advisory_ids_vec)
                },
            };
            tcb_levels_vec.push(tcb_level_app);
        }
    }

    Ok(TcbInfo {
        id: id_option,
        version,
        issue_date,
        next_update,
        fmspc,
        pce_id,
        tcb_type: view.tcb_type(),
        tcb_evaluation_data_number: view.tcb_evaluation_data_number(),
        tdx_module,
        tdx_module_identities: tdx_module_identities_option,
        tcb_levels: tcb_levels_vec,
    })
}
