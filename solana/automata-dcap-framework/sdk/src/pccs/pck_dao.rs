use super::{PCCS_PROGRAM_ID, PccsClient, automata_on_chain_pccs};
use anchor_client::solana_sdk::{
    compute_budget::ComputeBudgetInstruction,
    pubkey::Pubkey,
    signer::{Signer, keypair::Keypair},
};
use anyhow::Result;
use automata_on_chain_pccs::types::ZkvmSelector;
use automata_on_chain_pccs::{client::accounts, client::args};
use std::ops::Deref;
use std::str::FromStr;

use crate::CertificateAuthority;
use crate::shared::{get_certificate_tbs_and_digest, get_issuer_common_name};

impl<S: Clone + Deref<Target = impl Signer>> PccsClient<S> {

    pub async fn upload_pck_data(
        &self,
        data: &[u8],
        data_buffer_keypair: Option<Keypair>,
    ) -> Result<Pubkey> {
        let data_buffer_keypair = data_buffer_keypair.unwrap_or_else(|| Keypair::new());
        let data_buffer_pubkey = data_buffer_keypair.pubkey();
    
        let (digest, _) = get_certificate_tbs_and_digest(data);
    
        // Step 1: initialize the data buffer account
        self
            .init_data_buffer(data_buffer_keypair, digest, data.len() as u32)
            .await?;
    
        // Step 2: Upload the data to the data buffer account
        self
            .upload_chunks(data_buffer_pubkey, data, 512usize)
            .await?;
    
        Ok(data_buffer_pubkey)
    }
    
    /// Retrieves a PCK certificate from the blockchain.
    ///
    /// # Arguments
    ///
    /// * `qe_id` - Quoting Enclave ID
    /// * `pce_id` - Provisioning Certification Enclave ID
    /// * `tcbm` - Trusted Computing Base Manifest
    ///
    /// # Returns
    ///
    /// * `Result<PckCertificate>` - The PCK certificate account data
    pub async fn get_pck_certificate(
        &self,
        qe_id: String,
        pce_id: String,
        tcbm: String,
    ) -> Result<(Pubkey, Vec<u8>)> {
        let pck_certificate_pda = Pubkey::find_program_address(
            &[
                b"pck_cert",
                &qe_id.as_bytes()[..8],
                &pce_id.as_bytes()[..2],
                &tcbm.as_bytes()[..8],
            ],
            &PCCS_PROGRAM_ID,
        );
        let account = self
            .program
            .account::<automata_on_chain_pccs::accounts::PckCertificate>(pck_certificate_pda.0)
            .await?;
    
        Ok((pck_certificate_pda.0, account.cert_data))
    }
    
    /// Creates or updates a PCK (Provisioning Certification Key) certificate on-chain.
    ///
    /// PCK certificates are used in the Intel SGX attestation process to verify
    /// the authenticity of an enclave.
    ///
    /// # Arguments
    ///
    /// * `qe_id` - Quoting Enclave ID
    /// * `pce_id` - Provisioning Certification Enclave ID
    /// * `tcbm` - Trusted Computing Base Manifest
    /// * `data_buffer_pubkey` - Public key of the data buffer containing the certificate data
    ///
    /// # Returns
    ///
    /// * `Result<()>` - Success or error
    ///
    pub async fn upsert_pck_certificate(
        &self,
        data_buffer_pubkey: Pubkey,
        zkvm_verifier_program: Pubkey,
        qe_id: String,
        pce_id: String,
        tcbm: String,
        zkvm_selector: ZkvmSelector,
        proof: Vec<u8>,
    ) -> anyhow::Result<()> {
        let pck_certificate_pda = Pubkey::find_program_address(
            &[
                b"pck_cert",
                &qe_id.as_bytes()[..8],
                &pce_id.as_bytes()[..2],
                &tcbm.as_bytes()[..8],
            ],
            &PCCS_PROGRAM_ID,
        );
    
        let pck_data = self
            .program
            .account::<automata_on_chain_pccs::accounts::DataBuffer>(data_buffer_pubkey)
            .await?
            .data;
    
        let (_, pck_tbs) = get_certificate_tbs_and_digest(&pck_data);
        // THIS IS WRONG
        let pck_tbs_issuer_common_name =
            get_issuer_common_name(&pck_tbs).expect("Failed to get PCK issuer common name");
    
        let (issuer_pubkey, _) = self.get_pcs_certificate(
            CertificateAuthority::from_str(&pck_tbs_issuer_common_name).unwrap(),
            false,
        )
        .await?;
    
        let _tx = self
            .program
            .request()
            .accounts(accounts::UpsertPckCertificate {
                authority: self.program.payer(),
                pck_certificate: pck_certificate_pda.0,
                data_buffer: data_buffer_pubkey,
                issuer_ca: issuer_pubkey,
                zkvm_verifier_program,
                system_program: anchor_client::solana_sdk::system_program::ID,
            })
            .instruction(ComputeBudgetInstruction::set_compute_unit_limit(1_000_000))
            .args(args::UpsertPckCertificate {
                ca_type: CertificateAuthority::from_str(&pck_tbs_issuer_common_name)
                    .unwrap()
                    .into(),
                qe_id,
                pce_id,
                tcbm,
                zkvm_selector,
                proof,
            })
            .send()
            .await?;
        Ok(())
    }
    

}