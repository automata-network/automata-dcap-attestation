use super::setup_test;
use borsh::BorshDeserialize;
use solana_program_test::tokio;
use solana_sdk::account::ReadableAccount;

use crate::state::CounterAccountData;

#[tokio::test]
async fn test_counter_account_creation() {
    let test_env = setup_test().await;
    let counter_account = test_env
        .banks_client
        .get_account(test_env.counter_account)
        .await
        .unwrap()
        .unwrap();
    let counter_account_data = counter_account.data.clone();

    // check account owner
    assert_eq!(counter_account.owner, test_env.program_id);

    // check account data size
    assert_eq!(counter_account_data.len(), 8usize);

    // check account should not be executable
    assert!(!counter_account.executable());

    // check account data
    let counter_account_state =
        CounterAccountData::deserialize(&mut counter_account_data.as_slice()).unwrap();
    assert_eq!(counter_account_state.current_count(), 0u64);
}
