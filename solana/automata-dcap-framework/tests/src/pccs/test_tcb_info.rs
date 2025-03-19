use automata_on_chain_pccs::state::TcbType;

use super::{PccsTestConfig, PccsTestHarness};

#[test]
fn test_tcb_info_upsert() {

    let config = PccsTestConfig::default();
    let harness = PccsTestHarness::new(config);

    let tcb_info = "7b2276657273696f6e223a322c22697373756544617465223a22323032342d30362d31395430373a33343a32395a222c226e657874557064617465223a22323032342d30372d31395430373a33343a32395a222c22666d737063223a22303036303661303030303030222c227063654964223a2230303030222c2274636254797065223a302c227463624576616c756174696f6e446174614e756d626572223a31362c227463624c6576656c73223a5b7b22746362223a7b22736778746362636f6d70303173766e223a31322c22736778746362636f6d70303273766e223a31322c22736778746362636f6d70303373766e223a332c22736778746362636f6d70303473766e223a332c22736778746362636f6d70303573766e223a3235352c22736778746362636f6d70303673766e223a3235352c22736778746362636f6d70303773766e223a312c22736778746362636f6d70303873766e223a302c22736778746362636f6d70303973766e223a302c22736778746362636f6d70313073766e223a302c22736778746362636f6d70313173766e223a302c22736778746362636f6d70313273766e223a302c22736778746362636f6d70313373766e223a302c22736778746362636f6d70313473766e223a302c22736778746362636f6d70313573766e223a302c22736778746362636f6d70313673766e223a302c2270636573766e223a31337d2c2274636244617465223a22323032332d30382d30395430303a30303a30305a222c22746362537461747573223a22535748617264656e696e674e6565646564227d2c7b22746362223a7b22736778746362636f6d70303173766e223a31322c22736778746362636f6d70303273766e223a31322c22736778746362636f6d70303373766e223a332c22736778746362636f6d70303473766e223a332c22736778746362636f6d70303573766e223a3235352c22736778746362636f6d70303673766e223a3235352c22736778746362636f6d70303773766e223a302c22736778746362636f6d70303873766e223a302c22736778746362636f6d70303973766e223a302c22736778746362636f6d70313073766e223a302c22736778746362636f6d70313173766e223a302c22736778746362636f6d70313273766e223a302c22736778746362636f6d70313373766e223a302c22736778746362636f6d70313473766e223a302c22736778746362636f6d70313573766e223a302c22736778746362636f6d70313673766e223a302c2270636573766e223a31337d2c2274636244617465223a22323032332d30382d30395430303a30303a30305a222c22746362537461747573223a22436f6e66696775726174696f6e416e64535748617264656e696e674e6565646564227d2c7b22746362223a7b22736778746362636f6d70303173766e223a31312c22736778746362636f6d70303273766e223a31312c22736778746362636f6d70303373766e223a332c22736778746362636f6d70303473766e223a332c22736778746362636f6d70303573766e223a3235352c22736778746362636f6d70303673766e223a3235352c22736778746362636f6d70303773766e223a312c22736778746362636f6d70303873766e223a302c22736778746362636f6d70303973766e223a302c22736778746362636f6d70313073766e223a302c22736778746362636f6d70313173766e223a302c22736778746362636f6d70313273766e223a302c22736778746362636f6d70313373766e223a302c22736778746362636f6d70313473766e223a302c22736778746362636f6d70313573766e223a302c22736778746362636f6d70313673766e223a302c2270636573766e223a31337d2c2274636244617465223a22323032332d30322d31355430303a30303a30305a222c22746362537461747573223a224f75744f6644617465227d2c7b22746362223a7b22736778746362636f6d70303173766e223a31312c22736778746362636f6d70303273766e223a31312c22736778746362636f6d70303373766e223a332c22736778746362636f6d70303473766e223a332c22736778746362636f6d70303573766e223a3235352c22736778746362636f6d70303673766e223a3235352c22736778746362636f6d70303773766e223a302c22736778746362636f6d70303873766e223a302c22736778746362636f6d70303973766e223a302c22736778746362636f6d70313073766e223a302c22736778746362636f6d70313173766e223a302c22736778746362636f6d70313273766e223a302c22736778746362636f6d70313373766e223a302c22736778746362636f6d70313473766e223a302c22736778746362636f6d70313573766e223a302c22736778746362636f6d70313673766e223a302c2270636573766e223a31337d2c2274636244617465223a22323032332d30322d31355430303a30303a30305a222c22746362537461747573223a224f75744f6644617465436f6e66696775726174696f6e4e6565646564227d2c7b22746362223a7b22736778746362636f6d70303173766e223a372c22736778746362636f6d70303273766e223a392c22736778746362636f6d70303373766e223a332c22736778746362636f6d70303473766e223a332c22736778746362636f6d70303573766e223a3235352c22736778746362636f6d70303673766e223a3235352c22736778746362636f6d70303773766e223a312c22736778746362636f6d70303873766e223a302c22736778746362636f6d70303973766e223a302c22736778746362636f6d70313073766e223a302c22736778746362636f6d70313173766e223a302c22736778746362636f6d70313273766e223a302c22736778746362636f6d70313373766e223a302c22736778746362636f6d70313473766e223a302c22736778746362636f6d70313573766e223a302c22736778746362636f6d70313673766e223a302c2270636573766e223a31337d2c2274636244617465223a22323032322d30382d31305430303a30303a30305a222c22746362537461747573223a224f75744f6644617465227d2c7b22746362223a7b22736778746362636f6d70303173766e223a372c22736778746362636f6d70303273766e223a392c22736778746362636f6d70303373766e223a332c22736778746362636f6d70303473766e223a332c22736778746362636f6d70303573766e223a3235352c22736778746362636f6d70303673766e223a3235352c22736778746362636f6d70303773766e223a302c22736778746362636f6d70303873766e223a302c22736778746362636f6d70303973766e223a302c22736778746362636f6d70313073766e223a302c22736778746362636f6d70313173766e223a302c22736778746362636f6d70313273766e223a302c22736778746362636f6d70313373766e223a302c22736778746362636f6d70313473766e223a302c22736778746362636f6d70313573766e223a302c22736778746362636f6d70313673766e223a302c2270636573766e223a31337d2c2274636244617465223a22323032322d30382d31305430303a30303a30305a222c22746362537461747573223a224f75744f6644617465436f6e66696775726174696f6e4e6565646564227d2c7b22746362223a7b22736778746362636f6d70303173766e223a342c22736778746362636f6d70303273766e223a342c22736778746362636f6d70303373766e223a332c22736778746362636f6d70303473766e223a332c22736778746362636f6d70303573766e223a3235352c22736778746362636f6d70303673766e223a3235352c22736778746362636f6d70303773766e223a302c22736778746362636f6d70303873766e223a302c22736778746362636f6d70303973766e223a302c22736778746362636f6d70313073766e223a302c22736778746362636f6d70313173766e223a302c22736778746362636f6d70313273766e223a302c22736778746362636f6d70313373766e223a302c22736778746362636f6d70313473766e223a302c22736778746362636f6d70313573766e223a302c22736778746362636f6d70313673766e223a302c2270636573766e223a31317d2c2274636244617465223a22323032312d31312d31305430303a30303a30305a222c22746362537461747573223a224f75744f6644617465227d2c7b22746362223a7b22736778746362636f6d70303173766e223a342c22736778746362636f6d70303273766e223a342c22736778746362636f6d70303373766e223a332c22736778746362636f6d70303473766e223a332c22736778746362636f6d70303573766e223a3235352c22736778746362636f6d70303673766e223a3235352c22736778746362636f6d70303773766e223a302c22736778746362636f6d70303873766e223a302c22736778746362636f6d70303973766e223a302c22736778746362636f6d70313073766e223a302c22736778746362636f6d70313173766e223a302c22736778746362636f6d70313273766e223a302c22736778746362636f6d70313373766e223a302c22736778746362636f6d70313473766e223a302c22736778746362636f6d70313573766e223a302c22736778746362636f6d70313673766e223a302c2270636573766e223a31307d2c2274636244617465223a22323032302d31312d31315430303a30303a30305a222c22746362537461747573223a224f75744f6644617465227d2c7b22746362223a7b22736778746362636f6d70303173766e223a342c22736778746362636f6d70303273766e223a342c22736778746362636f6d70303373766e223a332c22736778746362636f6d70303473766e223a332c22736778746362636f6d70303573766e223a3235352c22736778746362636f6d70303673766e223a3235352c22736778746362636f6d70303773766e223a302c22736778746362636f6d70303873766e223a302c22736778746362636f6d70303973766e223a302c22736778746362636f6d70313073766e223a302c22736778746362636f6d70313173766e223a302c22736778746362636f6d70313273766e223a302c22736778746362636f6d70313373766e223a302c22736778746362636f6d70313473766e223a302c22736778746362636f6d70313573766e223a302c22736778746362636f6d70313673766e223a302c2270636573766e223a357d2c2274636244617465223a22323031382d30312d30345430303a30303a30305a222c22746362537461747573223a224f75744f6644617465227d5d7d";
    let tcb_info_data = hex::decode(tcb_info).unwrap();

    let num_chunks = PccsTestHarness::get_num_chunks(tcb_info_data.len(), 512);
    let data_buffer_pubkey = harness.init_data_buffer(tcb_info_data.len() as u32, num_chunks).unwrap();
    harness.upload_chunks(data_buffer_pubkey, &tcb_info_data, 512).unwrap();

    let tcb_type = TcbType::Sgx;
    let fmspc = "00606a000000";

    let _tx = harness.upsert_tcb_info(tcb_type, 2, fmspc.to_string(), data_buffer_pubkey).unwrap();

    let tcb_info = harness.get_tcb_info(tcb_type, 2, fmspc.to_string()).unwrap();

    let fmspc_bytes: [u8; 6] = hex::decode(fmspc).unwrap().try_into().unwrap();
    assert_eq!(tcb_info.version, 2);
    assert_eq!(tcb_info.tcb_type, tcb_type);
    assert_eq!(tcb_info.fmspc, fmspc_bytes);
    assert_eq!(tcb_info.data, tcb_info_data);
}
