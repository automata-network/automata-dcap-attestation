use super::{PCCS_PROGRAM_ID, PccsClient, automata_on_chain_pccs};
use crate::EnclaveIdentityType;
use anchor_client::solana_sdk::{
    compute_budget::ComputeBudgetInstruction,
    pubkey::Pubkey,
    signer::{Signer, keypair::Keypair},
};
use anyhow::Result;
use automata_on_chain_pccs::accounts::EnclaveIdentity as EnclaveIdentityAccount;
use automata_on_chain_pccs::types::ZkvmSelector;
use automata_on_chain_pccs::{client::accounts, client::args};
use dcap_rs::types::enclave_identity::{
    EnclaveIdentity as EnclaveIdentityObject, QuotingEnclaveIdentityAndSignature,
};
use dcap_rs::types::pod::enclave_identity::serialize::*;
use sha2::{Digest, Sha256};
use std::ops::Deref;

use crate::CertificateAuthority;

impl<S: Clone + Deref<Target = impl Signer>> PccsClient<S> {
    pub async fn upload_identity_data(
        &self,
        data: &[u8],
        data_buffer_keypair: Option<Keypair>,
    ) -> Result<Pubkey> {
        let data_buffer_keypair = data_buffer_keypair.unwrap_or_else(|| Keypair::new());
        let data_buffer_pubkey = data_buffer_keypair.pubkey();

        let identity_json: QuotingEnclaveIdentityAndSignature = serde_json::from_slice(data)?;
        let identity_body = identity_json.get_enclave_identity()?;
        let mut signature: [u8; 64] = [0; 64];
        signature.copy_from_slice(identity_json.signature.as_slice());

        let digest: [u8; 32] =
            Sha256::digest(identity_json.enclave_identity_raw.get().as_bytes()).into();

        let serialized_identity =
            SerializedEnclaveIdentity::from_rust_enclave_identity(&identity_body).unwrap();
        let identity_data = serialize_enclave_identity_pod(&serialized_identity, &signature);

        // Step 1: initialize the data buffer account
        self.init_data_buffer(data_buffer_keypair, digest, identity_data.len() as u32)
            .await?;

        // Step 2: Upload the data to the data buffer account
        self.upload_chunks(data_buffer_pubkey, identity_data.as_slice(), 512usize)
            .await?;

        Ok(data_buffer_pubkey)
    }

    /// Creates or updates enclave identity information on-chain.
    ///
    /// Enclave identity provides information about security properties of Intel SGX enclaves
    /// such as the Quoting Enclave (QE), TD Quoting Enclave (TD_QE), or Quote Verification Enclave (QVE).
    ///
    /// # Arguments
    ///
    /// * `id` - Enclave identity type (TdQe, QE, QVE)
    /// * `version` - Version number of the enclave identity
    /// * `data_buffer_pubkey` - Public key of the data buffer containing the identity data
    ///
    /// # Returns
    ///
    /// * `Result<()>` - Success or error
    ///
    pub async fn upsert_enclave_identity(
        &self,
        data_buffer_pubkey: Pubkey,
        zkvm_verifier_program: Pubkey,
        id: EnclaveIdentityType,
        version: u8,
        zkvm_selector: ZkvmSelector,
        proof: Vec<u8>,
    ) -> anyhow::Result<()> {
        let enclave_identity_pda = Pubkey::find_program_address(
            &[
                b"enclave_identity",
                id.common_name().as_bytes(),
                &version.to_le_bytes()[..1],
            ],
            &PCCS_PROGRAM_ID,
        );

        let (root_crl_pubkey, _) = self
            .get_pcs_certificate(CertificateAuthority::ROOT, true)
            .await?;

        let (issuer_pubkey, _) = self
            .get_pcs_certificate(CertificateAuthority::SIGNING, false)
            .await?;

        let _tx = self
            .program
            .request()
            .accounts(accounts::UpsertEnclaveIdentity {
                authority: self.program.payer(),
                enclave_identity: enclave_identity_pda.0,
                data_buffer: data_buffer_pubkey,
                root_crl: root_crl_pubkey,
                issuer_ca: issuer_pubkey,
                zkvm_verifier_program,
                system_program: anchor_client::solana_sdk::system_program::ID,
            })
            .instruction(ComputeBudgetInstruction::set_compute_unit_limit(1_000_000))
            .args(args::UpsertEnclaveIdentity {
                id: id.into(),
                version,
                zkvm_selector,
                proof, // Placeholder for the proof, to be filled in later
            })
            .send()
            .await?;
        Ok(())
    }

    /// Retrieves enclave identity information from the blockchain.
    ///
    /// # Arguments
    ///
    /// * `id` - Enclave identity type (TdQe, QE, QVE)
    /// * `version` - Version number of the enclave identity
    ///
    /// # Returns
    ///
    /// * `Result<EnclaveIdentity>` - The enclave identity account data
    pub async fn get_enclave_identity(
        &self,
        id: EnclaveIdentityType,
        version: u8,
    ) -> Result<(Pubkey, EnclaveIdentityObject)> {
        let (enclave_identity_pda_pubkey, _) = Pubkey::find_program_address(
            &[
                b"enclave_identity",
                id.common_name().as_bytes(),
                &version.to_le_bytes()[..1],
            ],
            &PCCS_PROGRAM_ID,
        );

        let enclave_identity_data = self
            .program
            .account::<EnclaveIdentityAccount>(enclave_identity_pda_pubkey)
            .await?;

        let (enclave_identity, _sig) =
            parse_enclave_identity_pod_bytes(enclave_identity_data.data.as_slice()).unwrap();

        Ok((enclave_identity_pda_pubkey, enclave_identity))
    }
}

impl From<EnclaveIdentityType> for automata_on_chain_pccs::types::EnclaveIdentityType {
    fn from(id: EnclaveIdentityType) -> Self {
        match id {
            EnclaveIdentityType::TdQe => automata_on_chain_pccs::types::EnclaveIdentityType::TdQe,
            EnclaveIdentityType::QE => automata_on_chain_pccs::types::EnclaveIdentityType::QE,
            EnclaveIdentityType::QVE => automata_on_chain_pccs::types::EnclaveIdentityType::QVE,
        }
    }
}

impl From<automata_on_chain_pccs::types::EnclaveIdentityType> for EnclaveIdentityType {
    fn from(id: automata_on_chain_pccs::types::EnclaveIdentityType) -> Self {
        match id {
            automata_on_chain_pccs::types::EnclaveIdentityType::TdQe => EnclaveIdentityType::TdQe,
            automata_on_chain_pccs::types::EnclaveIdentityType::QE => EnclaveIdentityType::QE,
            automata_on_chain_pccs::types::EnclaveIdentityType::QVE => EnclaveIdentityType::QVE,
        }
    }
}
