use std::{str::FromStr, sync::Arc};

use anchor_client::{
    Client, Cluster, Program,
    solana_client::rpc_client::RpcClient,
    solana_sdk::{
        commitment_config::CommitmentConfig,
        pubkey::Pubkey,
        signature::{Keypair, read_keypair_file},
    },
};

#[cfg(test)]
mod test_pck_certificate;

pub struct PccsTestConfig {
    pub program_id: String,
    pub rpc_url: String,
}

impl Default for PccsTestConfig {
    fn default() -> Self {
        Self {
            program_id: "H2w3Z4HMFws4VswB812AA5RvgaESGHTGWffSPRvcAoJn".to_string(),
            rpc_url: "http://localhost:8899".to_string(),
        }
    }
}

pub struct PccsTestHarness {
    program: Program<Arc<Keypair>>,
    _config: PccsTestConfig,
    _rpc_client: RpcClient,
}

impl PccsTestHarness {
    pub fn new(config: PccsTestConfig) -> Self {
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

    pub fn upsert_pck_certificate(
        &self,
        qe_id: String,
        pce_id: String,
        tcbm: String,
        cert_data: String,
    ) -> anyhow::Result<()> {
        let tx = self
            .program
            .request()
            .accounts(automata_on_chain_pccs::accounts::UpsertPckCertificate {
                authority: self.program.payer(),
                pck_certificate: self.program.payer(),
                system_program: anchor_client::solana_sdk::system_program::ID,
            })
            .args(automata_on_chain_pccs::instruction::UpsertPckCertificate {
                qe_id,
                pce_id,
                tcbm,
                cert_data,
            })
            .send()
            .expect("Failed to upsert PCK certificate");

        println!("Transaction signature: {}", tx);
        Ok(())
    }
}
