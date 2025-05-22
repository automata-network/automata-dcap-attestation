use super::{setup_test, store_verified_output, TestEnv};
use anyhow::Result;
use solana_program_test::tokio;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signer::Signer,
    system_program,
    transaction::Transaction,
};

#[tokio::test]
async fn test_delete_output_account() {
    let test_env = setup_test().await;

    // these outputs can be obtained from the autaomta-dcap-zkvm-cli repo.
    // see: https://github.com/automata-network/automata-dcap-zkvm-cli/

    let verified_output_bytes = hex::decode("02550004000000810790c06f000000040102000000000000000000000000009790d89a10210ec6968a773cee2ca05b5aa97309f36727a968527be4606fc19e6f73acce350946c9d46a9bf7a63f843000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000080e702060000000000f2dd2696f69b950645832bdc095ffd11247eeff687eeacdb57a58d2ddb9a9f94fea40c961e19460c00ffa31420ecbc180000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000998204508d58dcbfebe5e11c48669f7a921ac2da744dfb7d014ecdff2acdff1c9f665fdad52aadacf296a1df9909eb2383d100224f1716aeb431f7cb3cf028197dbd872487f27b0f6329ab17647dc9953c7014109818634f879e6550bc60f93eecfc42ff4d49278bfdbb0c77e570f4490cff10a2ee1ac11fbd2c2b49fa6cfa3cf1a1cb755c72522dd8a689e9d47906a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000278e753482976c8a7351fe2113609c7350d491cdae3d449eefc202fa41b2ad6840239cc2ba084c2d594b4e6dabeae0fcbf71c96daf0d0c9ecf0e9810c045790000000000678a107443c84ad5632ba264b434183c560d14b33b444e1e70b97a48d2d0cc66a5abae0b0de0b5aae34431815b937f711d928b600cd16c8e239e4d0745c138192e1ab4880fa74a3f32c80b978c8ad671395dabf24283eef9091bc3919fd39b9915a87f1adf3061c165c0191e2658256a2855cac9267f179aafb1990c9e918d6452816adf9953f245d005b9d7d8e36a842a60b51e5cf85b2c2072ae397c178535c9985b77e9c390c66c953d010f6cfea08cf5280cbb312b0648e0c968bbd2eeeb72af0f9f").unwrap();

    // store verified output
    let stored = store_verified_output(&test_env, &verified_output_bytes).await;
    assert!(stored.is_ok());

    // check output account state
    let output_pda_pubkey = stored.unwrap();
    let output_pda_account = test_env
        .banks_client
        .get_account(output_pda_pubkey.clone())
        .await
        .unwrap()
        .unwrap();

    let mut payer_account = test_env
        .banks_client
        .get_account(test_env.payer_keypair.pubkey().clone())
        .await
        .unwrap()
        .unwrap();

    let output_pda_rent_exempt_lamports_before = output_pda_account.lamports;
    let payer_account_lamports_before = payer_account.lamports;

    assert!(delete_output_account(&test_env, 0, &output_pda_pubkey)
        .await
        .is_ok());

    // output_pda_account has been deleted
    let output_pda_account_is_none = test_env
        .banks_client
        .get_account(output_pda_pubkey.clone())
        .await
        .unwrap()
        .is_none();
    assert!(output_pda_account_is_none);

    payer_account = test_env
        .banks_client
        .get_account(test_env.payer_keypair.pubkey().clone())
        .await
        .unwrap()
        .unwrap();
    let payer_account_lamports_after = payer_account.lamports;
    let payer_account_lamports_diff = payer_account_lamports_after - payer_account_lamports_before;
    assert_eq!(
        payer_account_lamports_diff,
        output_pda_rent_exempt_lamports_before - 5000 // 5000 lamports paid for txn fee
    );
}

async fn delete_output_account(env: &TestEnv, index: u64, output_pubkey: &Pubkey) -> Result<()> {
    let index_serialized = u64::to_le_bytes(index);

    let payer_pubkey = env.payer_keypair.pubkey().clone();
    let program_id = env.program_id.clone();

    let instruction_data: Vec<u8> = [vec![2], index_serialized.to_vec()].concat();

    let instruction = Instruction::new_with_bytes(
        program_id,
        &instruction_data,
        vec![
            AccountMeta::new(payer_pubkey, true),
            AccountMeta::new(output_pubkey.clone(), false),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
    );

    let recent_blockhash = &env.banks_client.get_latest_blockhash().await?;

    let mut tx = Transaction::new_with_payer(&[instruction], Some(&payer_pubkey));
    tx.sign(&[&env.payer_keypair], *recent_blockhash);
    env.banks_client.process_transaction(tx).await?;

    Ok(())
}
