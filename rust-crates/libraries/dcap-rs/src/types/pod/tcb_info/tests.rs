use super::serialize::*;
use super::zero_copy::*;
use crate::types::tcb_info::*;

use sha2::{Digest, Sha256};

#[test]
fn test_tcb_v2_sgx_bytemuck() {
    let tcb_data = include_bytes!("../../../../data/tcb_info_v2.json");

    println!("Original TCB data size: {}", tcb_data.len());

    let tcb_info_and_signature = serde_json::from_slice::<TcbInfoAndSignature>(tcb_data)
        .expect("Failed to deserialize TCB info and signature");
    let original_tcb_info = tcb_info_and_signature.get_tcb_info().unwrap();
    let mut signature: [u8; 64] = [0u8; 64];
    signature.copy_from_slice(tcb_info_and_signature.signature.as_slice());

    let serialized_tcb_info = SerializedTcbInfo::from_rust_tcb_info(&original_tcb_info)
        .expect("Serialization to SerializedTcbInfo failed for TcbV2");
    let pod_bytes = serialize_tcb_pod(&serialized_tcb_info, &signature);

    println!("Serialized TCB data size: {}", pod_bytes.len());

    let (parsed_tcb_info, parsed_signature) =
        parse_tcb_pod_bytes(&pod_bytes).expect("Parsing TcbPod bytes failed for TcbV2");
    assert_eq!(
        original_tcb_info, parsed_tcb_info,
        "Round-tripped TcbInfoV2 does not match original"
    );
    assert_eq!(
        signature, parsed_signature,
        "Round-tripped TcbInfoV2 signature does not match original"
    );

    // Integrity Check
    let original_tcb_info_hash =
        Sha256::digest(tcb_info_and_signature.tcb_info_raw.get().as_bytes());
    let parsed_tcb_info_string = serde_json::to_string(&parsed_tcb_info)
        .expect("Failed to serialize parsed TcbInfoV2 to JSON string");
    let parsed_tcb_info_hash = Sha256::digest(parsed_tcb_info_string.as_bytes());
    assert_eq!(
        original_tcb_info_hash, parsed_tcb_info_hash,
        "Parsed TcbInfoV2 hash does not match original"
    );

    // Test ZeroCopy for TcbV2
    let tcb_info_header_and_payload_bytes = &pod_bytes[64..];
    let tcb_info_zero_copy = TcbInfoZeroCopy::from_bytes(tcb_info_header_and_payload_bytes)
        .expect("Failed to create TcbInfoZeroCopy for TcbV2");

    assert_eq!(
        tcb_info_zero_copy.id_type_bytes(),
        &[0u8; 6],
        "ID Bytes should be zero for TcbV2"
    );
    assert_eq!(
        tcb_info_zero_copy.version(),
        original_tcb_info.version as u32
    );
    assert_eq!(
        tcb_info_zero_copy.issue_date_timestamp(),
        original_tcb_info.issue_date.timestamp()
    );
    assert_eq!(
        tcb_info_zero_copy.next_update_timestamp(),
        original_tcb_info.next_update.timestamp()
    );
    assert_eq!(tcb_info_zero_copy.fmspc(), original_tcb_info.fmspc_bytes());
    assert_eq!(
        tcb_info_zero_copy.pce_id(),
        original_tcb_info.pce_id_bytes()
    );
    assert_eq!(tcb_info_zero_copy.tcb_type(), original_tcb_info.tcb_type);
    assert_eq!(
        tcb_info_zero_copy.tcb_evaluation_data_number(),
        original_tcb_info.tcb_evaluation_data_number
    );
    assert!(
        tcb_info_zero_copy.tdx_module().is_none(),
        "TDX module should not be present in TcbV2"
    );
    assert_eq!(tcb_info_zero_copy.tdx_module_identities_count(), 0);

    let mut view_tcb_levels_iter = tcb_info_zero_copy.tcb_levels();
    let original_tcb_levels = &original_tcb_info.tcb_levels;

    // TCB Levels length check
    assert_eq!(
        tcb_info_zero_copy.tcb_levels_count(),
        original_tcb_levels.len() as u32
    );

    // iterate over TCB Levels
    for tcb_level in original_tcb_levels.iter() {
        let view_tcb_level = view_tcb_levels_iter
            .next()
            .unwrap()
            .expect("Failed to get TCB level from view");
        assert_eq!(
            view_tcb_level.tcb_date_timestamp(),
            tcb_level.tcb_date.timestamp()
        );
        assert_eq!(
            TcbStatus::try_from(view_tcb_level.tcb_status()).unwrap(),
            tcb_level.tcb_status
        );
        assert_eq!(
            view_tcb_level.advisory_ids_count(),
            0,
            "There should be no advisory IDs in TcbV2"
        );
        assert_eq!(view_tcb_level.pce_svn(), tcb_level.tcb.pcesvn());

        let sgx_components = tcb_level.tcb.sgx_tcb_components();
        for (i, view_sgx_component) in view_tcb_level.sgx_tcb_components().enumerate() {
            let view_sgx_component =
                view_sgx_component.expect("Failed to get SGX component from view");
            assert_eq!(view_sgx_component.cpusvn(), sgx_components[i]);
            assert_eq!(view_sgx_component.category_str().unwrap(), "");
            assert_eq!(view_sgx_component.component_type_str().unwrap(), "");
        }

        assert!(
            view_tcb_level.tdx_tcb_components().is_none(),
            "TDX components should not be present in TcbV2"
        );
        let view_advisory_ids_iter = view_tcb_level.advisory_ids();
        assert_eq!(
            view_advisory_ids_iter.count(),
            0,
            "Advisory IDs should not be present in TcbV2"
        );
    }
    assert_eq!(
        view_tcb_levels_iter.count(),
        0,
        "Expected no more TCB levels in the iterator"
    );
}

#[test]
fn test_tcb_v3_sgx_bytemuck() {
    let tcb_data = include_bytes!("../../../../data/tcb_info_v3_sgx.json");

    println!("Original TCB data size: {}", tcb_data.len());

    let tcb_info_and_signature = serde_json::from_slice::<TcbInfoAndSignature>(tcb_data)
        .expect("Failed to deserialize TCB info and signature");
    let original_tcb_info = tcb_info_and_signature.get_tcb_info().unwrap();
    let mut signature: [u8; 64] = [0u8; 64];
    signature.copy_from_slice(tcb_info_and_signature.signature.as_slice());

    let serialized_tcb_info = SerializedTcbInfo::from_rust_tcb_info(&original_tcb_info)
        .expect("Serialization to SerializedTcbInfo failed for TcbV3 SGX");
    let pod_bytes = serialize_tcb_pod(&serialized_tcb_info, &signature);

    println!("Serialized TCB data size: {}", pod_bytes.len());

    let (parsed_tcb_info, parsed_signature) =
        parse_tcb_pod_bytes(&pod_bytes).expect("Parsing TcbPod bytes failed for TcbV3 SGX");
    assert_eq!(
        original_tcb_info, parsed_tcb_info,
        "Round-tripped TcbInfoV3 does not match original"
    );
    assert_eq!(
        signature, parsed_signature,
        "Round-tripped TcbInfoV3 signature does not match original"
    );

    // Integrity Check
    let original_tcb_info_hash =
        Sha256::digest(tcb_info_and_signature.tcb_info_raw.get().as_bytes());
    let parsed_tcb_info_string = serde_json::to_string(&parsed_tcb_info)
        .expect("Failed to serialize parsed TcbInfoV3 SGX to JSON string");
    let parsed_tcb_info_hash = Sha256::digest(parsed_tcb_info_string.as_bytes());
    assert_eq!(
        original_tcb_info_hash, parsed_tcb_info_hash,
        "Parsed TcbInfoV2 hash does not match original"
    );

    // Test ZeroCopy for TcbV3 SGX
    let tcb_info_header_and_payload_bytes = &pod_bytes[64..];
    let tcb_info_zero_copy = TcbInfoZeroCopy::from_bytes(tcb_info_header_and_payload_bytes)
        .expect("Failed to create TcbInfoZeroCopy for TcbV3");

    // assert_eq!(tcb_info_zero_copy.id_type_bytes(), b"SGX", "ID Bytes should be zero for TcbV3");
    assert_eq!(
        tcb_info_zero_copy.version(),
        original_tcb_info.version as u32
    );
    assert_eq!(
        tcb_info_zero_copy.issue_date_timestamp(),
        original_tcb_info.issue_date.timestamp()
    );
    assert_eq!(
        tcb_info_zero_copy.next_update_timestamp(),
        original_tcb_info.next_update.timestamp()
    );
    assert_eq!(tcb_info_zero_copy.fmspc(), original_tcb_info.fmspc_bytes());
    assert_eq!(
        tcb_info_zero_copy.pce_id(),
        original_tcb_info.pce_id_bytes()
    );
    assert_eq!(tcb_info_zero_copy.tcb_type(), original_tcb_info.tcb_type);
    assert_eq!(
        tcb_info_zero_copy.tcb_evaluation_data_number(),
        original_tcb_info.tcb_evaluation_data_number
    );
    assert!(
        tcb_info_zero_copy.tdx_module().is_none(),
        "TDX module should not be present in TcbV3 SGX"
    );
    assert_eq!(tcb_info_zero_copy.tdx_module_identities_count(), 0);

    let mut view_tcb_levels_iter = tcb_info_zero_copy.tcb_levels();
    let original_tcb_levels = &original_tcb_info.tcb_levels;

    // TCB Levels length check
    assert_eq!(
        tcb_info_zero_copy.tcb_levels_count(),
        original_tcb_levels.len() as u32
    );

    // iterate over TCB Levels
    for tcb_level in original_tcb_levels.iter() {
        let view_tcb_level = view_tcb_levels_iter
            .next()
            .unwrap()
            .expect("Failed to get TCB level from view");
        assert_eq!(
            view_tcb_level.tcb_date_timestamp(),
            tcb_level.tcb_date.timestamp()
        );
        assert_eq!(
            TcbStatus::try_from(view_tcb_level.tcb_status()).unwrap(),
            tcb_level.tcb_status
        );
        assert_eq!(view_tcb_level.pce_svn(), tcb_level.tcb.pcesvn());

        let advisory_ids = tcb_level.advisory_ids.as_ref();
        if let Some(advisory_ids) = advisory_ids {
            assert_eq!(
                view_tcb_level.advisory_ids_count(),
                advisory_ids.len() as u32
            );
            let view_advisory_ids_iter = view_tcb_level.advisory_ids();
            for (i, view_advisory_id) in view_advisory_ids_iter.enumerate() {
                let view_advisory_id =
                    view_advisory_id.expect("Failed to get advisory ID from view");
                assert_eq!(view_advisory_id, advisory_ids[i].as_str());
            }
        }

        let tcb_v3 = if let Tcb::V3(tcb) = &tcb_level.tcb {
            tcb
        } else {
            panic!("Expected Tcb::V3 for SGX TCB level");
        };

        for (i, view_sgx_component) in view_tcb_level.sgx_tcb_components().enumerate() {
            let view_sgx_component =
                view_sgx_component.expect("Failed to get SGX component from view");
            let sgx_component = &tcb_v3.sgxtcbcomponents[i];
            assert_eq!(view_sgx_component.cpusvn(), sgx_component.svn);

            if let Some(category) = &sgx_component.category {
                assert_eq!(view_sgx_component.category_str().unwrap(), category);
            } else {
                assert_eq!(view_sgx_component.category_str().unwrap(), "");
            }

            if let Some(component_type) = &sgx_component.component_type {
                assert_eq!(
                    view_sgx_component.component_type_str().unwrap(),
                    component_type
                );
            } else {
                assert_eq!(view_sgx_component.component_type_str().unwrap(), "");
            }
        }

        assert!(
            view_tcb_level.tdx_tcb_components().is_none(),
            "TDX components should not be present in TcbV3 SGX"
        );
    }
    assert_eq!(
        view_tcb_levels_iter.count(),
        0,
        "Expected no more TCB levels in the iterator"
    );
}

#[test]
fn test_tcb_v3_tdx_bytemuck() {
    let tcb_data = include_bytes!("../../../../data/tcb_info_v3_tdx_0.json");

    println!("Original TCB data size: {}", tcb_data.len());

    let tcb_info_and_signature = serde_json::from_slice::<TcbInfoAndSignature>(tcb_data)
        .expect("Failed to deserialize TCB info and signature");
    let original_tcb_info = tcb_info_and_signature.get_tcb_info().unwrap();
    let mut signature: [u8; 64] = [0u8; 64];
    signature.copy_from_slice(tcb_info_and_signature.signature.as_slice());

    let serialized_tcb_info = SerializedTcbInfo::from_rust_tcb_info(&original_tcb_info)
        .expect("Serialization to SerializedTcbInfo failed for TcbV3 TDX");
    let pod_bytes = serialize_tcb_pod(&serialized_tcb_info, &signature);

    println!("Serialized TCB data size: {}", pod_bytes.len());

    let (parsed_tcb_info, parsed_signature) =
        parse_tcb_pod_bytes(&pod_bytes).expect("Parsing TcbPod bytes failed for TcbV3 TDX");
    assert_eq!(
        original_tcb_info, parsed_tcb_info,
        "Round-tripped TcbInfoV3 does not match original"
    );
    assert_eq!(
        signature, parsed_signature,
        "Round-tripped TcbInfoV3 signature does not match original"
    );

    // Integrity Check
    let original_tcb_info_hash =
        Sha256::digest(tcb_info_and_signature.tcb_info_raw.get().as_bytes());
    let parsed_tcb_info_string = serde_json::to_string(&parsed_tcb_info)
        .expect("Failed to serialize parsed TcbInfoV3 SGX to JSON string");
    let parsed_tcb_info_hash = Sha256::digest(parsed_tcb_info_string.as_bytes());
    assert_eq!(
        original_tcb_info_hash, parsed_tcb_info_hash,
        "Parsed TcbInfoV2 hash does not match original"
    );

    // Test ZeroCopy for TcbV3 TDX
    let tcb_info_header_and_payload_bytes = &pod_bytes[64..];
    let tcb_info_zero_copy = TcbInfoZeroCopy::from_bytes(tcb_info_header_and_payload_bytes)
        .expect("Failed to create TcbInfoZeroCopy for TcbV3");

    // assert_eq!(tcb_info_zero_copy.id_type_bytes(), b"SGX", "ID Bytes should be zero for TcbV3");
    assert_eq!(
        tcb_info_zero_copy.version(),
        original_tcb_info.version as u32
    );
    assert_eq!(
        tcb_info_zero_copy.issue_date_timestamp(),
        original_tcb_info.issue_date.timestamp()
    );
    assert_eq!(
        tcb_info_zero_copy.next_update_timestamp(),
        original_tcb_info.next_update.timestamp()
    );
    assert_eq!(tcb_info_zero_copy.fmspc(), original_tcb_info.fmspc_bytes());
    assert_eq!(
        tcb_info_zero_copy.pce_id(),
        original_tcb_info.pce_id_bytes()
    );
    assert_eq!(tcb_info_zero_copy.tcb_type(), original_tcb_info.tcb_type);
    assert_eq!(
        tcb_info_zero_copy.tcb_evaluation_data_number(),
        original_tcb_info.tcb_evaluation_data_number
    );

    if let Some(tdx_module) = tcb_info_zero_copy.tdx_module() {
        assert_eq!(
            tdx_module.mrsigner(),
            original_tcb_info
                .tdx_module
                .as_ref()
                .unwrap()
                .mrsigner_bytes()
        );
        assert_eq!(
            tdx_module.attributes(),
            original_tcb_info
                .tdx_module
                .as_ref()
                .unwrap()
                .attributes_bytes()
        );
        assert_eq!(
            tdx_module.attributes_mask(),
            original_tcb_info
                .tdx_module
                .as_ref()
                .unwrap()
                .attributes_mask_bytes()
        );
    } else {
        panic!("TDX module should be present in TcbV3 TDX");
    }

    if tcb_info_zero_copy.tdx_module_identities_count() > 0 {
        let tdx_module_identities_iter = tcb_info_zero_copy.tdx_module_identities().enumerate();
        let original_tdx_module_identities = &original_tcb_info.tdx_module_identities.unwrap();
        for (i, tdx_module_identity) in tdx_module_identities_iter {
            let tdx_module_identity =
                tdx_module_identity.expect("Failed to get TDX module identity from view");
            assert_eq!(
                tdx_module_identity.mrsigner(),
                original_tdx_module_identities[i].mrsigner_bytes()
            );
            assert_eq!(
                tdx_module_identity.attributes(),
                original_tdx_module_identities[i].attributes_bytes()
            );
            assert_eq!(
                tdx_module_identity.attributes_mask(),
                original_tdx_module_identities[i].attributes_mask_bytes()
            );
            assert_eq!(
                tdx_module_identity.id_str().unwrap(),
                original_tdx_module_identities[i].id.as_str()
            );

            let tcb_module_identity_tcb_count = tdx_module_identity.tcb_levels_count();
            assert_eq!(
                tcb_module_identity_tcb_count,
                original_tdx_module_identities[i].tcb_levels.len() as u32
            );
            if tcb_module_identity_tcb_count > 0 {
                let mut view_tcb_levels_iter = tdx_module_identity.tcb_levels();
                let original_tcb_levels = &original_tdx_module_identities[i].tcb_levels;
                for tcb_level in original_tcb_levels.iter() {
                    let view_tcb_level = view_tcb_levels_iter
                        .next()
                        .unwrap()
                        .expect("Failed to get TDX Module Identity TCB level from view");
                    assert_eq!(
                        view_tcb_level.tcb_date_timestamp(),
                        tcb_level.tcb_date.timestamp()
                    );
                    assert_eq!(
                        TcbStatus::try_from(view_tcb_level.tcb_status()).unwrap(),
                        tcb_level.tcb_status
                    );
                    assert_eq!(view_tcb_level.tcb_isvsvn(), tcb_level.tcb.isvsvn);

                    let advisory_ids = tcb_level.advisory_ids.as_ref();
                    if let Some(advisory_ids) = advisory_ids {
                        assert_eq!(
                            view_tcb_level.advisory_ids_count(),
                            advisory_ids.len() as u32
                        );
                        let view_advisory_ids_iter = view_tcb_level.advisory_ids();
                        for (j, view_advisory_id) in view_advisory_ids_iter.enumerate() {
                            let view_advisory_id =
                                view_advisory_id.expect("Failed to get advisory ID from view");
                            assert_eq!(view_advisory_id, advisory_ids[j].as_str());
                        }
                    }
                }
            }
        }
    }

    let mut view_tcb_levels_iter = tcb_info_zero_copy.tcb_levels();
    let original_tcb_levels = &original_tcb_info.tcb_levels;

    // TCB Levels length check
    assert_eq!(
        tcb_info_zero_copy.tcb_levels_count(),
        original_tcb_levels.len() as u32
    );

    // iterate over TCB Levels
    for tcb_level in original_tcb_levels.iter() {
        let view_tcb_level = view_tcb_levels_iter
            .next()
            .unwrap()
            .expect("Failed to get TCB level from view");
        assert_eq!(
            view_tcb_level.tcb_date_timestamp(),
            tcb_level.tcb_date.timestamp()
        );
        assert_eq!(
            TcbStatus::try_from(view_tcb_level.tcb_status()).unwrap(),
            tcb_level.tcb_status
        );
        assert_eq!(view_tcb_level.pce_svn(), tcb_level.tcb.pcesvn());

        let advisory_ids = tcb_level.advisory_ids.as_ref();
        if let Some(advisory_ids) = advisory_ids {
            assert_eq!(
                view_tcb_level.advisory_ids_count(),
                advisory_ids.len() as u32
            );
            let view_advisory_ids_iter = view_tcb_level.advisory_ids();
            for (i, view_advisory_id) in view_advisory_ids_iter.enumerate() {
                let view_advisory_id =
                    view_advisory_id.expect("Failed to get advisory ID from view");
                assert_eq!(view_advisory_id, advisory_ids[i].as_str());
            }
        }

        let tcb_v3 = if let Tcb::V3(tcb) = &tcb_level.tcb {
            tcb
        } else {
            panic!("Expected Tcb::V3 for SGX TCB level");
        };

        for (i, view_sgx_component) in view_tcb_level.sgx_tcb_components().enumerate() {
            let view_sgx_component =
                view_sgx_component.expect("Failed to get SGX component from view");
            let sgx_component = &tcb_v3.sgxtcbcomponents[i];
            assert_eq!(view_sgx_component.cpusvn(), sgx_component.svn);

            if let Some(category) = &sgx_component.category {
                assert_eq!(view_sgx_component.category_str().unwrap(), category);
            } else {
                assert_eq!(view_sgx_component.category_str().unwrap(), "");
            }

            if let Some(component_type) = &sgx_component.component_type {
                assert_eq!(
                    view_sgx_component.component_type_str().unwrap(),
                    component_type
                );
            } else {
                assert_eq!(view_sgx_component.component_type_str().unwrap(), "");
            }
        }
    }
    assert_eq!(
        view_tcb_levels_iter.count(),
        0,
        "Expected no more TCB levels in the iterator"
    );
}
