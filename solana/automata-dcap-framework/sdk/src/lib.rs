mod models;
mod pccs_client;
mod utils;
mod verifier_client;

use std::ops::Deref;

use anchor_client::{
    Client, Cluster,
    solana_sdk::{commitment_config::CommitmentConfig, signature::Signature, signer::Signer},
};
use anchor_lang::prelude::Pubkey;
use automata_dcap_verifier::types::ZkvmSelector;
pub use models::*;
pub use pccs_client::*;
pub use utils::*;
pub use verifier_client::*;

pub struct Sdk<S> {
    provider: Client<S>,
    verifier_client: VerifierClient<S>,
    pccs_client: PccsClient<S>,
    signer: S,
}

impl<S: Clone + Deref<Target = impl Signer>> Sdk<S> {
    pub fn new(signer: S, cluster: Option<Cluster>) -> Self {
        let cluster = cluster.unwrap_or(Cluster::Localnet);
        let provider =
            Client::new_with_options(cluster, signer.clone(), CommitmentConfig::confirmed());
        let verifier_client = VerifierClient::new(&provider).unwrap();
        let pccs_client = PccsClient::new(&provider).unwrap();
        Self {
            provider,
            verifier_client,
            pccs_client,
            signer,
        }
    }

    pub fn anchor_provider(&self) -> &Client<S> {
        &self.provider
    }

    pub fn signer(&self) -> &S {
        &self.signer
    }

    pub fn verifier_client(&self) -> &VerifierClient<S> {
        &self.verifier_client
    }

    pub fn pccs_client(&self) -> &PccsClient<S> {
        &self.pccs_client
    }

    pub async fn verify_quote(
        &self,
        zkvm_selector: ZkvmSelector,
        zkvm_verifier_program: Pubkey,
        bytes: &[u8],
    ) -> anyhow::Result<(Pubkey, Vec<Signature>)> {
        let quote_buffer_pubkey = self
            .verifier_client
            .init_quote_buffer(bytes.len() as u32)
            .await?;

        self.verifier_client
            .upload_chunks(quote_buffer_pubkey, bytes, 512)
            .await?;

        let verified_output_pubkey = self
            .verifier_client
            .get_verified_output_pubkey(quote_buffer_pubkey)
            .await?;

        let signatures = self
            .verifier_client
            .verify_quote(quote_buffer_pubkey, zkvm_selector, zkvm_verifier_program)
            .await?;

        Ok((verified_output_pubkey, signatures))
    }
}
