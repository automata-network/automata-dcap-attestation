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

use crate::CertificateAuthority;
use crate::shared::get_certificate_tbs_and_digest;

impl<S: Clone + Deref<Target = impl Signer>> PccsClient<S> {
    pub async fn upload_pcs_data(
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

    /// Retrieves a PCS certificate from the blockchain.
    ///
    /// # Arguments
    ///
    /// * `ca_type` - Certificate Authority type (ROOT, PLATFORM, PROCESSOR, SIGNING)
    /// * `is_crl` - Whether this is a Certificate Revocation List
    ///
    /// # Returns
    ///
    /// * `Result<PcsCertificate>` - The PCS certificate account data
    pub async fn get_pcs_certificate(
        &self,
        ca_type: CertificateAuthority,
        is_crl: bool,
    ) -> Result<(Pubkey, Vec<u8>)> {
        let pcs_certificate_pda = Pubkey::find_program_address(
            &[
                b"pcs_cert",
                ca_type.common_name().as_bytes(),
                &[is_crl as u8],
            ],
            &PCCS_PROGRAM_ID,
        );

        let account = self
            .program
            .account::<automata_on_chain_pccs::accounts::PcsCertificate>(pcs_certificate_pda.0)
            .await?;

        let pcs_certificate_data = account.cert_data;

        Ok((pcs_certificate_pda.0, pcs_certificate_data))
    }

     /// Creates or updates a PCS (Provisioning Certification Service) certificate on-chain.
    ///
    /// PCS certificates are part of the Intel certificate hierarchy used in attestation.
    /// This includes root CA certificates, platform certificates, processor certificates,
    /// and potentially their certificate revocation lists (CRLs).
    ///
    /// # Arguments
    ///
    /// * `ca_type` - Certificate Authority type (ROOT, PLATFORM, PROCESSOR, SIGNING)
    /// * `is_crl` - Whether this is a Certificate Revocation List
    /// * `data_buffer_pubkey` - Public key of the data buffer containing the certificate data
    ///
    /// # Returns
    ///
    /// * `Result<()>` - Success or error
    ///
    pub async fn upsert_pcs_certificate(
        &self,
        data_buffer_pubkey: Pubkey,
        zkvm_verifier_program: Pubkey,
        ca_type: CertificateAuthority,
        is_crl: bool,
        zkvm_selector: ZkvmSelector,
        proof: Vec<u8>,
    ) -> anyhow::Result<()> {
        let pcs_certificate_pda = Pubkey::find_program_address(
            &[
                b"pcs_cert",
                ca_type.common_name().as_bytes(),
                &[is_crl as u8],
            ],
            &PCCS_PROGRAM_ID,
        );
    
        let issuer_pubkey = if ca_type == CertificateAuthority::ROOT && !is_crl {
            // if upserting the root, the issuer is itself
            pcs_certificate_pda.0
        } else {
            let issuer_ca = if !is_crl {
                CertificateAuthority::ROOT
            } else {
                ca_type
            };
    
            let (issuer_pubkey, _) = self.get_pcs_certificate( issuer_ca, false).await?;
    
            issuer_pubkey
        };
    
        if ca_type == CertificateAuthority::ROOT && !is_crl {
            let _tx = self
                .program
                .request()
                .accounts(accounts::UpsertRootCa {
                    authority: self.program.payer(),
                    root_ca: pcs_certificate_pda.0,
                    data_buffer: data_buffer_pubkey,
                    zkvm_verifier_program,
                    system_program: anchor_client::solana_sdk::system_program::ID,
                })
                .instruction(ComputeBudgetInstruction::set_compute_unit_limit(1_000_000))
                .args(args::UpsertRootCa {
                    zkvm_selector,
                    proof: proof,
                })
                .send()
                .await?;
        } else {
            let _tx = self
                .program
                .request()
                .accounts(accounts::UpsertPcsCertificate {
                    authority: self.program.payer(),
                    pcs_certificate: pcs_certificate_pda.0,
                    data_buffer: data_buffer_pubkey,
                    zkvm_verifier_program,
                    issuer_ca: issuer_pubkey,
                    system_program: anchor_client::solana_sdk::system_program::ID,
                })
                .instruction(ComputeBudgetInstruction::set_compute_unit_limit(1_000_000))
                .args(args::UpsertPcsCertificate {
                    ca_type: ca_type.into(),
                    is_crl,
                    zkvm_selector,
                    proof: proof,
                })
                .send()
                .await?;
        }
    
        Ok(())
    }

}

impl From<CertificateAuthority> for automata_on_chain_pccs::types::CertificateAuthority {
    fn from(ca_type: CertificateAuthority) -> Self {
        match ca_type {
            CertificateAuthority::ROOT => automata_on_chain_pccs::types::CertificateAuthority::ROOT,
            CertificateAuthority::PLATFORM => {
                automata_on_chain_pccs::types::CertificateAuthority::PLATFORM
            },
            CertificateAuthority::PROCESSOR => {
                automata_on_chain_pccs::types::CertificateAuthority::PROCESSOR
            },
            CertificateAuthority::SIGNING => {
                automata_on_chain_pccs::types::CertificateAuthority::SIGNING
            },
        }
    }
}

impl From<automata_on_chain_pccs::types::CertificateAuthority> for CertificateAuthority {
    fn from(ca_type: automata_on_chain_pccs::types::CertificateAuthority) -> Self {
        match ca_type {
            automata_on_chain_pccs::types::CertificateAuthority::ROOT => CertificateAuthority::ROOT,
            automata_on_chain_pccs::types::CertificateAuthority::PLATFORM => {
                CertificateAuthority::PLATFORM
            },
            automata_on_chain_pccs::types::CertificateAuthority::PROCESSOR => {
                CertificateAuthority::PROCESSOR
            },
            automata_on_chain_pccs::types::CertificateAuthority::SIGNING => {
                CertificateAuthority::SIGNING
            },
        }
    }
}