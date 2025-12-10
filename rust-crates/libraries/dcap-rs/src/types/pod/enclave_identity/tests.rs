// src/types/pod/enclave_identity/tests.rs
use crate::types::enclave_identity::{QeTcbStatus, QuotingEnclaveIdentityAndSignature};
use crate::types::pod::enclave_identity::serialize::{
    SerializedEnclaveIdentity, parse_enclave_identity_pod_bytes, serialize_enclave_identity_pod,
};
use crate::types::pod::enclave_identity::zero_copy::EnclaveIdentityZeroCopy;
use sha2::{Digest, Sha256};

// #[test]
// fn test_enclave_identity_bytemuck() {
//     let enclave_identity_data = include_bytes!("../../../../data/identityv2_0.json");

//     println!("original data size: {}", enclave_identity_data.len());

//     let enclave_identity_parsed: QuotingEnclaveIdentityAndSignature =
//         serde_json::from_slice(enclave_identity_data).unwrap();
//     let original_enclave_identity = enclave_identity_parsed.get_enclave_identity().unwrap();
//     let mut signature: [u8; 64] = [0; 64];
//     signature.copy_from_slice(&enclave_identity_parsed.signature);

//     let serialized_enclave_identity =
//         SerializedEnclaveIdentity::from_rust_enclave_identity(&original_enclave_identity).unwrap();
//     let pod_bytes = serialize_enclave_identity_pod(&serialized_enclave_identity, &signature);

//     println!("serialized data size: {}", pod_bytes.len());

//     let (parsed_enclave_identity, parsed_signature) =
//         parse_enclave_identity_pod_bytes(&pod_bytes).unwrap();

//     assert_eq!(original_enclave_identity, parsed_enclave_identity);
//     assert_eq!(&signature, &parsed_signature);

//     // Integrity check
//     let original_hash = Sha256::digest(
//         enclave_identity_parsed
//             .enclave_identity_raw
//             .get()
//             .as_bytes(),
//     );
//     let parsed_enclave_identity_string = serde_json::to_string(&parsed_enclave_identity).unwrap();
//     let parsed_hash = Sha256::digest(parsed_enclave_identity_string.as_bytes());
//     assert_eq!(original_hash, parsed_hash);

//     // Test ZeroCopy
//     let enclave_identity_zero_copy_bytes = &pod_bytes[64..];
//     let enclave_identity_zero_copy =
//         EnclaveIdentityZeroCopy::from_bytes(enclave_identity_zero_copy_bytes).unwrap();

//     assert_eq!(
//         enclave_identity_zero_copy.id_byte(),
//         u8::from(original_enclave_identity.id)
//     );

//     assert_eq!(
//         enclave_identity_zero_copy.version(),
//         original_enclave_identity.version
//     );

//     assert_eq!(
//         enclave_identity_zero_copy.issue_date_timestamp(),
//         original_enclave_identity.issue_date.timestamp()
//     );

//     assert_eq!(
//         enclave_identity_zero_copy.next_update_timestamp(),
//         original_enclave_identity.next_update.timestamp()
//     );

//     assert_eq!(
//         enclave_identity_zero_copy.tcb_evaluation_data_number(),
//         original_enclave_identity.tcb_evaluation_data_number
//     );

//     assert_eq!(
//         enclave_identity_zero_copy.miscselect_bytes(),
//         original_enclave_identity.miscselect_bytes()
//     );

//     assert_eq!(
//         enclave_identity_zero_copy.miscselect_mask_bytes(),
//         original_enclave_identity.miscselect_mask_bytes()
//     );

//     assert_eq!(
//         enclave_identity_zero_copy.attributes_bytes(),
//         original_enclave_identity.attributes_bytes()
//     );

//     assert_eq!(
//         enclave_identity_zero_copy.attributes_mask_bytes(),
//         original_enclave_identity.attributes_mask_bytes()
//     );

//     assert_eq!(
//         enclave_identity_zero_copy.mrsigner_bytes(),
//         original_enclave_identity.mrsigner_bytes()
//     );

//     assert_eq!(
//         enclave_identity_zero_copy.isvprodid(),
//         original_enclave_identity.isvprodid
//     );

//     let mut enclave_identity_zero_copy_tcb_levels_iter = enclave_identity_zero_copy.tcb_levels();
//     let original_enclave_identity_tcb_levels = &original_enclave_identity.tcb_levels;

//     assert_eq!(
//         enclave_identity_zero_copy.tcb_levels_count(),
//         original_enclave_identity_tcb_levels.len() as u32
//     );

//     for tcb_level in original_enclave_identity_tcb_levels.iter() {
//         let zero_copy_tcb_level = enclave_identity_zero_copy_tcb_levels_iter
//             .next()
//             .unwrap()
//             .expect("Failed to get next ZeroCopy TCB level");
//         assert_eq!(zero_copy_tcb_level.isvsvn(), tcb_level.tcb.isvsvn);
//         assert_eq!(
//             zero_copy_tcb_level.tcb_date_timestamp(),
//             tcb_level.tcb_date.timestamp()
//         );
//         assert_eq!(
//             QeTcbStatus::try_from(zero_copy_tcb_level.tcb_status_byte()).unwrap(),
//             tcb_level.tcb_status
//         );

//         if let Some(advisory_ids) = tcb_level.advisory_ids.as_ref() {
//             let mut zero_copy_advisory_ids_iter = zero_copy_tcb_level.advisory_ids();
//             for advisory_id in advisory_ids.iter() {
//                 let zero_copy_advisory_id = zero_copy_advisory_ids_iter
//                     .next()
//                     .unwrap()
//                     .expect("Failed to get next ZeroCopy advisory ID");
//                 assert_eq!(zero_copy_advisory_id, advisory_id);
//             }
//         } else {
//             assert_eq!(zero_copy_tcb_level.advisory_ids_count(), 0);
//         }
//     }
// }
