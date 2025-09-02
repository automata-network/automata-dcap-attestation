use super::{get_current_count, send_proof_to_verify, setup_test, store_verified_output};
use crate::state::OutputAccountData;
use borsh::BorshDeserialize;
use solana_program_test::tokio;
use solana_sdk::signer::Signer;

/// Consumed 363k CU
#[tokio::test]
async fn test_risc0_dcap_verifier() {

    let test_env = setup_test().await;

    // these outputs can be obtained from the automata-dcap-zkvm-cli repo.
    // see: https://github.com/automata-network/automata-dcap-zkvm-cli/

    let proof_bytes = hex::decode("1850aa52559f1d4a858a48b788b52bdd963888e29465a59ca4dace241ad1aeef2b1796d0acb6ea9f4d77a60a0555f28c85867e62b91ac8d0473ff017c88883da077c6be0d1140a77f0ab695679470472cc32f55ebdcf735e9d52ff4a53d3b685020772e77e8e94578796fd6cc122420a77c1c0ba8dff1c6e07e53e30da46d483147732f37ffb72fda399256a551beb49da688ea7cbdcf268fbc15695c3db42a40569e5093c75654a1390cb1fe9c57c360a8f338f66d61ae1115d4584faecc36f238a9eb4cfecea8d3e4995a354dbe5c4bc12db6a12da41e376931548110fb3c008c01d08cf9e8afb7fe661befbb5afce139c9a1ba1b6c10562645ce60954ab48").unwrap();
    let verified_output_bytes = hex::decode("02550004000000810790c06f000000040102000000000000000000000000009790d89a10210ec6968a773cee2ca05b5aa97309f36727a968527be4606fc19e6f73acce350946c9d46a9bf7a63f843000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000080e702060000000000f2dd2696f69b950645832bdc095ffd11247eeff687eeacdb57a58d2ddb9a9f94fea40c961e19460c00ffa31420ecbc180000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000998204508d58dcbfebe5e11c48669f7a921ac2da744dfb7d014ecdff2acdff1c9f665fdad52aadacf296a1df9909eb2383d100224f1716aeb431f7cb3cf028197dbd872487f27b0f6329ab17647dc9953c7014109818634f879e6550bc60f93eecfc42ff4d49278bfdbb0c77e570f4490cff10a2ee1ac11fbd2c2b49fa6cfa3cf1a1cb755c72522dd8a689e9d47906a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000278e753482976c8a7351fe2113609c7350d491cdae3d449eefc202fa41b2ad6840239cc2ba084c2d594b4e6dabeae0fcbf71c96daf0d0c9ecf0e9810c04579000000000067a1c97526bfe4de343d160db8c6e91dfa058e2669f130a165acdf3d29ddbcead7ae195e472509cb7f6530561a16654d93b5c51206af4a6a874d59f8da5d5f93e25496040fa74a3f32c80b978c8ad671395dabf24283eef9091bc3919fd39b9915a87f1adf3061c165c0191e2658256a2855cac9267f179aafb1990c9e918d6452816adf9953f245d005b9d7d8e36a842a60b51e5cf85b2c2072ae397c178535c9985b77ddda10bf8d35a769eecc37227eccfc994fe037229a6eef201cf84a14cbf472b9").unwrap();

    // store verified output
    let stored = store_verified_output(&test_env, &verified_output_bytes).await;
    assert!(stored.is_ok());

    // check counter account state
    assert_eq!(get_current_count(&test_env).await.unwrap(), 1u64);

    // check output account state
    let output_pda_pubkey = stored.unwrap();
    let mut output_pda_account = test_env
        .banks_client
        .get_account(output_pda_pubkey.clone())
        .await
        .unwrap()
        .unwrap();
    let mut output_pda_account_state =
        OutputAccountData::deserialize(&mut output_pda_account.data.as_slice()).unwrap();

    // check account owner
    assert_eq!(output_pda_account.owner, test_env.program_id);

    // check account data
    assert_eq!(output_pda_account_state.verified, false);
    assert_eq!(
        output_pda_account_state.close_authority,
        test_env.payer_keypair.pubkey()
    );
    assert_eq!(output_pda_account_state.output, verified_output_bytes);

    assert!(send_proof_to_verify(&test_env, 0, 1, &proof_bytes)
        .await
        .is_ok());

    // check output account state
    output_pda_account = test_env
        .banks_client
        .get_account(output_pda_pubkey.clone())
        .await
        .unwrap()
        .unwrap();
    output_pda_account_state =
        OutputAccountData::deserialize(&mut output_pda_account.data.as_slice()).unwrap();

    assert_eq!(output_pda_account_state.verified, true);
}
