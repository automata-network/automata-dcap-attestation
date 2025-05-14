use super::{PCCS_PROGRAM_ID, PccsClient, automata_on_chain_pccs};
use crate::TcbType;
use anchor_client::solana_sdk::{
    compute_budget::ComputeBudgetInstruction,
    pubkey::Pubkey,
    signer::{Signer, keypair::Keypair},
};
use anyhow::Result;
use automata_on_chain_pccs::types::ZkvmSelector;
use automata_on_chain_pccs::{client::accounts, client::args};
use dcap_rs::types::tcb_info::{TcbInfo, TcbInfoAndSignature};
use sha2::{Digest, Sha256};
use std::ops::Deref;

use crate::CertificateAuthority;

impl<S: Clone + Deref<Target = impl Signer>> PccsClient<S> {
    pub async fn upload_tcb_data(
        &self,
        data: &[u8],
        data_buffer_keypair: Option<Keypair>,
    ) -> Result<Pubkey> {
        let data_buffer_keypair = data_buffer_keypair.unwrap_or_else(|| Keypair::new());
        let data_buffer_pubkey = data_buffer_keypair.pubkey();

        let tcb_info_json: TcbInfoAndSignature = serde_json::from_slice(data)?;
        let tcb_info_body = tcb_info_json.get_tcb_info()?;
        let tcb_info_data = tcb_info_body.to_borsh_bytes()?;

        let digest: [u8; 32] = Sha256::digest(tcb_info_json.tcb_info_raw.get().as_bytes()).into();

        // Step 1: initialize the data buffer account
        self.init_data_buffer(data_buffer_keypair, digest, tcb_info_data.len() as u32)
            .await?;

        // Step 2: Upload the data to the data buffer account
        self.upload_chunks(data_buffer_pubkey, tcb_info_data.as_slice(), 512usize)
            .await?;

        Ok(data_buffer_pubkey)
    }

    /// Retrieves TCB information from the blockchain.
    ///
    /// # Arguments
    ///
    /// * `tcb_type` - TCB type (Sgx or Tdx)
    /// * `fmspc` - Family-Model-Stepping-Platform-CustomSKU (FMSPC) value
    /// * `version` - Version number of the TCB info
    ///
    /// # Returns
    ///
    /// * `Result<TcbInfo>` - The TCB info account data
    pub async fn get_tcb_info(
        &self,
        tcb_type: TcbType,
        fmspc: [u8; 6],
        version: u8,
    ) -> Result<(Pubkey, TcbInfo)> {
        let tcb_info_pda = Pubkey::find_program_address(
            &[
                b"tcb_info",
                tcb_type.common_name().as_bytes(),
                &version.to_le_bytes()[..1],
                &fmspc,
            ],
            &PCCS_PROGRAM_ID,
        );
        let account = self
            .program
            .account::<automata_on_chain_pccs::accounts::TcbInfo>(tcb_info_pda.0)
            .await?;

        Ok((
            tcb_info_pda.0,
            TcbInfo::from_borsh_bytes(account.data.as_slice())?,
        ))
    }

    /// Creates or updates TCB (Trusted Computing Base) information on-chain.
    ///
    /// TCB information describes the security properties and status of Intel SGX or TDX
    /// platforms, including security advisories and patch status.
    ///
    /// # Arguments
    ///
    /// * `tcb_type` - TCB type (Sgx or Tdx)
    /// * `version` - Version number of the TCB info
    /// * `fmspc` - Family-Model-Stepping-Platform-CustomSKU (FMSPC) value, a 6-byte identifier
    /// * `data_buffer_pubkey` - Public key of the data buffer containing the TCB info
    ///
    /// # Returns
    ///
    /// * `Result<()>` - Success or error
    pub async fn upsert_tcb_info(
        &self,
        data_buffer_pubkey: Pubkey,
        zkvm_verifier_program: Pubkey,
        tcb_type: TcbType,
        version: u8,
        fmspc: [u8; 6],
        zkvm_selector: ZkvmSelector,
        proof: Vec<u8>,
    ) -> anyhow::Result<()> {
        let tcb_info_pda = Pubkey::find_program_address(
            &[
                b"tcb_info",
                tcb_type.common_name().as_bytes(),
                &version.to_le_bytes()[..1],
                &fmspc,
            ],
            &self.program.id(),
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
            .accounts(accounts::UpsertTcbInfo {
                authority: self.program.payer(),
                tcb_info: tcb_info_pda.0,
                data_buffer: data_buffer_pubkey,
                root_crl: root_crl_pubkey,
                issuer_ca: issuer_pubkey,
                zkvm_verifier_program,
                system_program: anchor_client::solana_sdk::system_program::ID,
            })
            .instruction(ComputeBudgetInstruction::set_compute_unit_limit(1_000_000))
            .args(args::UpsertTcbInfo {
                tcb_type: tcb_type.into(),
                version,
                fmspc,
                zkvm_selector,
                proof,
            })
            .send()
            .await?;
        Ok(())
    }
}

impl From<TcbType> for automata_on_chain_pccs::types::TcbType {
    fn from(tcb_type: TcbType) -> Self {
        match tcb_type {
            TcbType::Sgx => automata_on_chain_pccs::types::TcbType::Sgx,
            TcbType::Tdx => automata_on_chain_pccs::types::TcbType::Tdx,
        }
    }
}

impl From<automata_on_chain_pccs::types::TcbType> for TcbType {
    fn from(tcb_type: automata_on_chain_pccs::types::TcbType) -> Self {
        match tcb_type {
            automata_on_chain_pccs::types::TcbType::Sgx => TcbType::Sgx,
            automata_on_chain_pccs::types::TcbType::Tdx => TcbType::Tdx,
        }
    }
}