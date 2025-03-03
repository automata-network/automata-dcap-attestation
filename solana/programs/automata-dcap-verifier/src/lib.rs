mod instructions;

use solana_program::{
    account_info::AccountInfo, entrypoint, entrypoint::ProgramResult, msg, pubkey::Pubkey,
};

entrypoint!(process_instruction);

pub fn process_instruction(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    msg!("Hello, world!");
    Ok(())
}


#[cfg(test)]
mod test {

    use solana_program_test::*;
    use solana_sdk::{instruction::Instruction, pubkey::Pubkey, signer::Signer, transaction::Transaction};


    #[tokio::test]
    async fn test_hello_world() {

        let program_id = Pubkey::new_unique();
        let mut program_test = ProgramTest::default();

        // Add the program to the test environment
        program_test.add_program("automata_dcap_verifier", program_id, None);

        let (banks_client, payer, last_blockhash) = program_test.start().await;

        // 1. Create Instruction
        let instruction = Instruction {
            program_id,
            accounts: vec![],
            data: vec![],
        };

        // 2. Create Transaction
        let mut transaction = Transaction::new_with_payer(&[instruction], Some(&payer.pubkey()));


        // 3. Sign Transaction
        transaction.sign(&[&payer], last_blockhash);

        // 4. Send Transaction
        let result = banks_client.process_transaction(transaction).await;
        assert!(result.is_ok());


    }
}
