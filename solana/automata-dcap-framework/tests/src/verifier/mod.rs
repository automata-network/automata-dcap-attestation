use anchor_client::{
    Client, Cluster, Program,
    anchor_lang::AccountDeserialize,
    solana_client::nonblocking::rpc_client::RpcClient,
    solana_sdk::{
        commitment_config::CommitmentConfig,
        pubkey::Pubkey,
        signature::{Keypair, read_keypair_file},
        signer::Signer,
    },
};
use std::{str::FromStr, sync::Arc};

#[cfg(test)]
mod test_quote_chunking;

pub struct TestConfig {
    pub program_id: String,
    pub rpc_url: String,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            program_id: "CfZXhDGoTxezVjEJ5eWr4Wu8GFpzqJsMAyzkevWupTBV".to_string(),
            rpc_url: "http://localhost:8899".to_string(),
        }
    }
}

pub struct VerifierTestHarness {
    program: Program<Arc<Keypair>>,
    _config: TestConfig,
    _rpc_client: RpcClient,
}

impl VerifierTestHarness {
    pub fn new(config: TestConfig) -> Self {
        let anchor_wallet =
            std::env::var("ANCHOR_WALLET").expect("ANCHOR_WALLET environment variable not set");
        let payer = read_keypair_file(&anchor_wallet).expect("Failed to read keypair file");

        let payer = Arc::new(payer);

        let client = Client::new_with_options(
            Cluster::Custom(config.rpc_url.clone(), config.rpc_url.clone()),
            payer,
            CommitmentConfig::confirmed(),
        );

        let program_id = Pubkey::from_str(&config.program_id).expect("Invalid program ID");

        let program = client
            .program(program_id)
            .expect("Failed to create program client");

        let rpc_client =
            RpcClient::new_with_commitment(config.rpc_url.clone(), CommitmentConfig::confirmed());

        Self {
            program,
            _config: config,
            _rpc_client: rpc_client,
        }
    }

    pub fn init_quote_buffer(&self, total_size: u32, num_chunks: u8) -> anyhow::Result<Pubkey> {
        let quote_buffer_keypair = Keypair::new();
        let quote_buffer_pubkey = quote_buffer_keypair.pubkey();

        let tx = self
            .program
            .request()
            .accounts(automata_dcap_framework::accounts::InitQuoteBuffer {
                owner: self.program.payer(),
                data_buffer: quote_buffer_pubkey,
                system_program: anchor_client::solana_sdk::system_program::ID,
            })
            .args(automata_dcap_framework::instruction::InitQuoteBuffer {
                total_size,
                num_chunks,
            })
            .signer(&quote_buffer_keypair)
            .send()
            .expect("Failed to initialize quote buffer");

        println!("Transaction signature: {}", tx);
        Ok(quote_buffer_pubkey)
    }

    pub fn upload_chunks(
        &self,
        quote_buffer_pubkey: Pubkey,
        data: &[u8],
        chunk_size: usize,
    ) -> anyhow::Result<()> {
        for (i, chunk) in data.chunks(chunk_size).enumerate() {
            let chunk_index = i as u8;
            let offset = i as u32 * chunk_size as u32;
            let chunk_data = chunk.to_vec();

            let tx = self
                .program
                .request()
                .accounts(automata_dcap_framework::accounts::AddQuoteChunk {
                    owner: self.program.payer(),
                    data_buffer: quote_buffer_pubkey,
                })
                .args(automata_dcap_framework::instruction::AddQuoteChunk {
                    chunk_index,
                    offset,
                    chunk_data,
                })
                .send()
                .expect("Failed to add quote chunk");

            println!("Transaction signature: {}", tx);
        }
        Ok(())
    }

    pub fn get_account<T: AccountDeserialize>(&self, pubkey: Pubkey) -> anyhow::Result<T> {
        let account = self
            .program
            .account::<T>(pubkey)
            .expect("Failed to fetch account");
        Ok(account)
    }

    pub fn get_payer(&self) -> Pubkey {
        self.program.payer().clone()
    }

    pub fn get_num_chunks(data_len: usize, chunk_size: usize) -> u8 {
        ((data_len as f64 / chunk_size as f64).ceil()) as u8
    }
}
