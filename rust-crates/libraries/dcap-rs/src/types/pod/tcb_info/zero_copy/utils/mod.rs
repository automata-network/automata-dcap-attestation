use super::{
    error::ZeroCopyError,
    structs::{TcbInfoZeroCopy, TcbLevelZeroCopy},
};
use crate::types::{
    quote::{Quote, QuoteBody},
    sgx_x509::SgxPckExtension,
};

pub fn lookup<'a>(
    pck_extension: &SgxPckExtension,
    tcb_info: &TcbInfoZeroCopy<'a>,
    quote: &Quote,
) -> Result<(u8, u8, Vec<String>), ZeroCopyError> {
    let mut sgx_tcb_status_u8: u8 = 0; // Default, will be overwritten
    let mut advisory_ids: Vec<String> = Vec::new();
    let mut found_sgx_match_index: Option<usize> = None;

    for (idx, tcb_level_res) in tcb_info.tcb_levels().enumerate() {
        let tcb_level = tcb_level_res?;
        if pck_in_tcb_level_zc(&tcb_level, pck_extension)? {
            sgx_tcb_status_u8 = tcb_level.tcb_status();
            advisory_ids = tcb_level
                .advisory_ids()
                .map(|res| res.map(|s| s.to_string()))
                .collect::<Result<Vec<String>, ZeroCopyError>>()?;
            found_sgx_match_index = Some(idx);
            break;
        }
    }

    if found_sgx_match_index.is_none() {
        // As per original TcbStatus::lookup, this is an error condition.
        return Err(ZeroCopyError::NoMatchingSgxTcbLevel);
    }

    let mut tdx_tcb_status_u8 = 7u8; // TcbStatus::Unspecified = 7

    if let QuoteBody::Td10QuoteBody(tdx_quote_body) = &quote.body {
        // Start iterating from the found sgx matching level's index
        for tdx_tcb_levels_res in tcb_info.tcb_levels().skip(found_sgx_match_index.unwrap()) {
            let tdx_tcb_level = tdx_tcb_levels_res?;
            if let Some(tdx_tcb_levels_iter) = tdx_tcb_level.tdx_tcb_components() {
                let mut tdx_components_match = true;
                // tdx_tcb_levels_iter yields 16 components
                // tdx_quote_body.tee_tcb_svn is [u8; 16]
                for (tdx_tcb_components_res, quote_svn_val) in
                    tdx_tcb_levels_iter.zip(tdx_quote_body.tee_tcb_svn.iter())
                {
                    let platform_comp = tdx_tcb_components_res?;
                    if platform_comp.cpusvn() > *quote_svn_val {
                        tdx_components_match = false;
                        break;
                    }
                }

                if tdx_components_match {
                    tdx_tcb_status_u8 = tdx_tcb_level.tcb_status();
                    advisory_ids = tdx_tcb_level
                        .advisory_ids()
                        .map(|res| res.map(|s| s.to_string()))
                        .collect::<Result<Vec<String>, ZeroCopyError>>()?;
                    break; // Found matching TDX TCB level
                }
            } else {
                // This TCB level in TCB Info does not have TDX components,
                // but we have a TDX quote. This is an inconsistency.
                // Original code returns: anyhow!("did not find tdx tcb components in tcb info when Td10QuoteBody is provided for the quote")
                return Err(ZeroCopyError::MissingTdxComponentsInTcbInfo);
            }
        }
        // If loop finishes without break, tdx_tcb_status_u8 remains Unspecified if no match was found
        // or updated if a match was found. This matches original logic where if no TDX match, status isn't further updated.
    }

    Ok((sgx_tcb_status_u8, tdx_tcb_status_u8, advisory_ids))
}

fn pck_in_tcb_level_zc<'a>(
    level: &TcbLevelZeroCopy<'a>,
    pck_extension: &SgxPckExtension,
) -> Result<bool, ZeroCopyError> {
    let pck_compsvn = &pck_extension.tcb.compsvn; // This is [u8; 16]

    // sgx_tcb_components() yields an iterator for 16 components
    for (idx, comp_res) in level.sgx_tcb_components().enumerate() {
        let comp = comp_res?;
        // The TcbComponentIter for sgx_tcb_components is expected to yield 16 components.
        // pck_compsvn is also fixed at 16.
        if idx < 16 {
            if pck_compsvn[idx] < comp.cpusvn() {
                return Ok(false);
            }
        } else {
            // Should not happen if TcbComponentIter is correctly implemented for 16 components
            return Err(ZeroCopyError::UnexpectedSgxComponentCount);
        }
    }

    // Check PCE SVN
    if pck_extension.tcb.pcesvn < level.pce_svn() {
        return Ok(false);
    }

    Ok(true)
}

// #[cfg(all(test, not(feature = "zero-copy")))]
// mod tests {
//     use crate::types::pod::tcb_info::serialize::{SerializedTcbInfo, serialize_tcb_pod};
//     use crate::types::{
//         pod::tcb_info::zero_copy::TcbInfoZeroCopy,
//         quote::Quote,
//         tcb_info::{TcbInfoAndSignature, TcbStatus},
//     };

//     #[test]
//     pub fn test_zero_copy_tcb_lookup() {
//         let quote_bytes = include_bytes!("../../../../../../data/quote_tdx.bin");
//         let tcb_info_json_bytes =
//             include_bytes!("../../../../../../data/tcb_info_v3_with_tdx_module.json");

//         // Parse the quote and extract the PCK SGX extension
//         let quote = Quote::read(&mut quote_bytes.as_slice()).unwrap();
//         let pck_extension = quote.signature.get_pck_extension().unwrap();

//         // Parse TCB Info and convert to ZeroCopy
//         let tcb_info_json: TcbInfoAndSignature =
//             serde_json::from_slice(tcb_info_json_bytes).unwrap();
//         let tcb_info = tcb_info_json.get_tcb_info().unwrap();
//         let mut signature = [0u8; 64];
//         signature.copy_from_slice(tcb_info_json.signature.as_slice());
//         let serialized_tcb_info = SerializedTcbInfo::from_rust_tcb_info(&tcb_info).unwrap();
//         let serialize_tcb_info_bytes = serialize_tcb_pod(&serialized_tcb_info, &signature);
//         let tcb_info_zero_copy =
//             TcbInfoZeroCopy::from_bytes(&serialize_tcb_info_bytes[64..]).unwrap();

//         // Perform the lookup
//         // Start with TcbStatus::lookup
//         let (sgx_tcb_status_expected, tdx_tcb_status_expected, advisory_ids_expected) =
//             TcbStatus::lookup(&pck_extension, &tcb_info, &quote).unwrap();

//         // ZeroCopy lookup
//         let (sgx_tcb_status_zc, tdx_tcb_status_zc, advisory_ids_zc) =
//             super::lookup(&pck_extension, &tcb_info_zero_copy, &quote).unwrap();

//         assert_eq!(
//             sgx_tcb_status_expected,
//             TcbStatus::try_from(sgx_tcb_status_zc).unwrap(),
//             "SGX TCB status mismatch"
//         );
//         assert_eq!(
//             tdx_tcb_status_expected,
//             TcbStatus::try_from(tdx_tcb_status_zc).unwrap(),
//             "TDX TCB status mismatch"
//         );
//         assert_eq!(
//             advisory_ids_expected, advisory_ids_zc,
//             "Advisory IDs mismatch"
//         );
//     }
// }
