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
use crate::shared::{get_certificate_tbs_and_digest, get_crl_tbs_and_digest};

/// Intel PCS Data Access Object Module
/// This module provides methods to upload and retrieve the following collaterals from the Onchain PCCS Program:
/// - Intel Root CA
/// - Intel SGX PCK Platform CA
/// - Intel SGX PCK Processor CA
/// - Intel TCB Signing CA
/// - Root CRL
/// - PCK Platform CRL
/// - PCK Processor CRL

impl<S: Clone + Deref<Target = impl Signer>> PccsClient<S> {
    
    /// Uploads PCS data (encoded in DER) and its tbs digest to the buffer
    /// 
    /// # Parameters
    /// 
    /// - `is_crl` - Whether this is a Certificate Revocation List
    /// - `data` - The data to be uploaded
    /// - `data_buffer_keypair` - Optional: keypair for the data buffer account. If none is provided,
    /// a new keypair will be generated.
    /// 
    /// # Returns
    /// - `Result<Pubkey>` - The public key of the data buffer account
    pub async fn upload_pcs_data(
        &self,
        is_crl: bool,
        data: &[u8],
        data_buffer_keypair: Option<Keypair>,
    ) -> Result<Pubkey> {
        let data_buffer_keypair = data_buffer_keypair.unwrap_or_else(|| Keypair::new());
        let data_buffer_pubkey = data_buffer_keypair.pubkey();

        let digest = if is_crl {
            get_crl_tbs_and_digest(data).0
        } else {
            get_certificate_tbs_and_digest(data).0
        };

        // Step 1: initialize the data buffer account
        self.init_data_buffer(data_buffer_keypair, digest, data.len() as u32)
            .await?;

        // Step 2: Upload the data to the data buffer account
        self.upload_chunks(data_buffer_pubkey, data, 512usize)
            .await?;

        Ok(data_buffer_pubkey)
    }

    /// Retrieves a PCS certificate or CRL and its corresponding public key from the blockchain.
    ///
    /// # Parameters
    ///
    /// - `ca_type` - Certificate Authority type (ROOT, PLATFORM, PROCESSOR, SIGNING)
    /// - `is_crl` - Whether this is a Certificate Revocation List
    ///
    /// # Returns
    ///
    /// - `Result<(Pubkey, Vec<u8>)>` - A tuple containing the public key of the PCS certificate, and the raw data
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

        let pcs_certificate_data = account.cert_data[0..account.cert_data_size as usize]
            .to_vec();

        Ok((pcs_certificate_pda.0, pcs_certificate_data.to_vec()))
    }

    /// Updates a PCS (Provisioning Certification Service) certificate on-chain.
    ///
    /// This method reads and validates the uploaded certificate data from the data buffer
    /// and then transfers it to the corresponding PCS certificate PDA.
    /// 
    /// If the PDA already exists, it will overwrite the existing certificate.
    ///
    /// # Parameters
    ///
    /// - `data_buffer_pubkey` - Public key of the data buffer containing the certificate data
    /// - `zkvm_verifier_program` - Public key of the ZKVM verifier program
    /// - `ca_type` - Certificate Authority type (ROOT, PLATFORM, PROCESSOR, SIGNING)
    /// - `zkvm_selector` - The ZKVM selector (currently only supports RiscZero)
    /// - `proof` - The SNARK proof bytes for proving ECDSA verification
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
        zkvm_selector: ZkvmSelector,
        proof: Vec<u8>,
    ) -> Result<()> {
        let pcs_certificate_pda = Pubkey::find_program_address(
            &[
                b"pcs_cert",
                ca_type.common_name().as_bytes(),
                &[false as u8],
            ],
            &PCCS_PROGRAM_ID,
        );

        if ca_type == CertificateAuthority::ROOT {
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
            let (issuer_pubkey, _) = self
                .get_pcs_certificate(CertificateAuthority::ROOT, false)
                .await?;

            let (root_crl_pubkey, _) = self
                .get_pcs_certificate(CertificateAuthority::ROOT, true)
                .await?;

            let _tx = self
                .program
                .request()
                .accounts(accounts::UpsertPcsCertificate {
                    authority: self.program.payer(),
                    pcs_certificate: pcs_certificate_pda.0,
                    data_buffer: data_buffer_pubkey,
                    zkvm_verifier_program,
                    root_crl: root_crl_pubkey,
                    issuer_ca: issuer_pubkey,
                    system_program: anchor_client::solana_sdk::system_program::ID,
                })
                .instruction(ComputeBudgetInstruction::set_compute_unit_limit(1_000_000))
                .args(args::UpsertPcsCertificate {
                    ca_type: ca_type.into(),
                    zkvm_selector,
                    proof: proof,
                })
                .send()
                .await?;
        }

        Ok(())
    }

    /// Updates a PCS Certificate Revocation List (CRL) on-chain.
    ///
    /// This method reads and validates the uploaded certificate data from the data buffer
    /// and then transfers it to the corresponding PCS certificate PDA.
    /// 
    /// If the PDA already exists, it will overwrite the existing certificate.
    ///
    /// # Parameters
    ///
    /// - `data_buffer_pubkey` - Public key of the data buffer containing the certificate data
    /// - `zkvm_verifier_program` - Public key of the ZKVM verifier program
    /// - `ca_type` - Certificate Authority type (ROOT, PLATFORM, PROCESSOR, SIGNING)
    /// - `zkvm_selector` - The ZKVM selector (currently only supports RiscZero)
    /// - `proof` - The SNARK proof bytes for proving ECDSA verification
    ///
    /// # Returns
    ///
    /// * `Result<()>` - Success or error
    ///
    pub async fn upsert_pcs_crl(
        &self,
        data_buffer_pubkey: Pubkey,
        zkvm_verifier_program: Pubkey,
        ca_type: CertificateAuthority,
        zkvm_selector: ZkvmSelector,
        proof: Vec<u8>,
    ) -> Result<()> {
        assert!(
            ca_type != CertificateAuthority::SIGNING,
            "Intel TCB Signing CA does not issue CRLs"
        );

        let pcs_crl_pda = Pubkey::find_program_address(
            &[b"pcs_cert", ca_type.common_name().as_bytes(), &[true as u8]],
            &PCCS_PROGRAM_ID,
        );

        let (issuer_pubkey, _) = self.get_pcs_certificate(ca_type, false).await?;

        if ca_type == CertificateAuthority::ROOT {
            let _tx = self
                .program
                .request()
                .accounts(accounts::UpsertRootCrl {
                    authority: self.program.payer(),
                    root_crl: pcs_crl_pda.0,
                    root_ca: issuer_pubkey,
                    data_buffer: data_buffer_pubkey,
                    zkvm_verifier_program,
                    system_program: anchor_client::solana_sdk::system_program::ID,
                })
                .instruction(ComputeBudgetInstruction::set_compute_unit_limit(1_000_000))
                .args(args::UpsertRootCrl {
                    zkvm_selector,
                    proof: proof,
                })
                .send()
                .await?;
        } else {
            let (root_crl_pubkey, _) = self
                .get_pcs_certificate(CertificateAuthority::ROOT, true)
                .await?;

            let _tx = self
                .program
                .request()
                .accounts(accounts::UpsertPcsCrl {
                    authority: self.program.payer(),
                    pcs_crl: pcs_crl_pda.0,
                    data_buffer: data_buffer_pubkey,
                    zkvm_verifier_program,
                    root_crl: root_crl_pubkey,
                    issuer_ca: issuer_pubkey,
                    system_program: anchor_client::solana_sdk::system_program::ID,
                })
                .instruction(ComputeBudgetInstruction::set_compute_unit_limit(1_000_000))
                .args(args::UpsertPcsCrl {
                    ca_type: ca_type.into(),
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
