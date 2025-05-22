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

/// Intel PCK Certificate Data Access Object Module
/// This method provides methods to upload and retrieve PCK certificates from the Onchain PCCS program.

impl<S: Clone + Deref<Target = impl Signer>> PccsClient<S> {

    /// Uploads PCK Certificate (encoded in DER) data and its tbs digest to the buffer
    /// 
    /// # Parameters
    /// 
    /// - `data` - The data to be uploaded
    /// - `data_buffer_keypair` - Optional: keypair for the data buffer account. If none is provided,
    /// a new keypair will be generated.
    /// 
    /// # Returns
    /// - `Result<Pubkey>` - The public key of the data buffer account
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
    
    /// Retrieves a PCK certificate and its public key from the blockchain.
    ///
    /// # Parameters
    ///
    /// - `qe_id` - Quoting Enclave ID
    /// - `pce_id` - Provisioning Certification Enclave ID
    /// - `tcbm` - Trusted Computing Base Manifest
    ///
    /// # Returns
    ///
    /// - `Result<(Pubkey, Vec<u8>)>` - A tuple containing the public key of the PCK certificate and the raw certificate data.
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
    
    /// Updates a PCK (Provisioning Certification Key) certificate on-chain.
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
    /// - `qe_id` - Quoting Enclave ID
    /// - `pce_id` - Provisioning Certification Enclave ID
    /// - `tcbm` - Trusted Computing Base Manifest
    /// - `zkvm_selector` - The ZKVM selector (currently only supports RiscZero)
    /// - `proof` - The SNARK proof bytes for proving ECDSA verification
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
    
        let pck_cert_type = CertificateAuthority::from_str(&pck_tbs_issuer_common_name).unwrap();

        let (pck_crl_pubkey, _) = self
            .get_pcs_certificate(pck_cert_type, true)
            .await?;

        let (root_crl_pubkey, _) = self
            .get_pcs_certificate(CertificateAuthority::ROOT, true)
            .await?;

        let (issuer_pubkey, _) = self.get_pcs_certificate(
            pck_cert_type,
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
                pck_crl: pck_crl_pubkey,
                root_crl: root_crl_pubkey,
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