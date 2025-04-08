use sdk::TcbType;

use crate::pccs::get_signer;

#[tokio::test]
async fn test_tcb_info_upsert_v3_sgx() {

    let tcb_info_data = include_bytes!("../../data/tcb_info_v3_sgx.json");


    let client = sdk::PccsClient::new(get_signer()).unwrap();
    let num_chunks = sdk::get_num_chunks(tcb_info_data.len(), 512);
    let data_buffer_pubkey = client.init_data_buffer(tcb_info_data.len() as u32, num_chunks).await.unwrap();
    client.upload_chunks(data_buffer_pubkey, tcb_info_data, 512).await.unwrap();

    let tcb_type = TcbType::Sgx;
    let fmspc = "00A067110000";

    let _tx = client.upsert_tcb_info(tcb_type, 3, fmspc.to_string(), data_buffer_pubkey).await.unwrap();

    let tcb_info = client.get_tcb_info(tcb_type, fmspc.to_string(), 3).await.unwrap();

    let fmspc_bytes: [u8; 6] = hex::decode(fmspc).unwrap().try_into().unwrap();
    let actual_tcb_type: TcbType = tcb_info.tcb_type.into();
    assert_eq!(tcb_info.version, 3);
    assert_eq!(actual_tcb_type, tcb_type);
    assert_eq!(tcb_info.fmspc, fmspc_bytes);
    assert_eq!(tcb_info.data, tcb_info_data);
}

#[tokio::test]
async fn test_tcb_info_upsert_v3_tdx() {

    let tcb_info_data = include_bytes!("../../data/tcb_info_v3_with_tdx_module.json");


    let client = sdk::PccsClient::new(get_signer()).unwrap();
    let num_chunks = sdk::get_num_chunks(tcb_info_data.len(), 512);
    let data_buffer_pubkey = client.init_data_buffer(tcb_info_data.len() as u32, num_chunks).await.unwrap();
    client.upload_chunks(data_buffer_pubkey, tcb_info_data, 512).await.unwrap();

    let tcb_type = TcbType::Tdx;
    let fmspc = "00806f050000";

    let _tx = client.upsert_tcb_info(tcb_type, 3, fmspc.to_string(), data_buffer_pubkey).await.unwrap();

    let tcb_info = client.get_tcb_info(tcb_type, fmspc.to_string(), 3).await.unwrap();

    let fmspc_bytes: [u8; 6] = hex::decode(fmspc).unwrap().try_into().unwrap();
    let actual_tcb_type: TcbType = tcb_info.tcb_type.into();
    assert_eq!(tcb_info.version, 3);
    assert_eq!(actual_tcb_type, tcb_type);
    assert_eq!(tcb_info.fmspc, fmspc_bytes);
    assert_eq!(tcb_info.data, tcb_info_data);
}
