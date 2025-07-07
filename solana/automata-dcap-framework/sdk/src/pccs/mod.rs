pub mod enclave_identity_dao;
pub mod fmspc_tcb_dao;
pub mod pck_dao;
pub mod pcs_dao;

pub use dcap_p256_zk_lib::InputType as EcdsaZkVerifyInputType;

use crate::shared::negate_g1;
use crate::models::*;

use std::ops::Deref;
use anchor_client::{
    Client, Program,
    solana_sdk::signer::{Signer, keypair::Keypair},
};
use anchor_lang::{declare_program, prelude::Pubkey};

declare_program!(automata_on_chain_pccs);
use automata_on_chain_pccs::accounts::DataBuffer;
use automata_on_chain_pccs::{client::accounts, client::args};

/// The Solana program ID for the PCCS (Provisioning Certificate Caching Service) on-chain program.
pub const PCCS_PROGRAM_ID: Pubkey = automata_on_chain_pccs::ID;

/// A client for interacting with the PCCS (Provisioning Certificate Caching Service) program on Solana.
///
/// The PCCS program provides on-chain storage and validation for Intel SGX/TDX attestation-related
/// certificates and metadata, including:
/// - PCK (Provisioning Certification Key) Certificates
/// - PCS (Provisioning Certification Service) Certificates
/// - Enclave Identity information
/// - TCB (Trusted Computing Base) information
///
/// This client abstracts the complexity of interacting with the on-chain program by providing
/// methods to initialize data buffers, upload data in chunks, and manage various certificate types.
pub struct PccsClient<S> {
    pub program: Program<S>,
}

impl<S: Clone + Deref<Target = impl Signer>> PccsClient<S> {
    pub fn new(client: &Client<S>) -> anyhow::Result<Self> {
        let program = client.program(automata_on_chain_pccs::ID)?;
        Ok(Self { program })
    }

    /// Initializes a new data buffer account on-chain for storing data for all collaterals.
    ///
    /// # Parameters
    ///
    /// * `data_buffer_keypair` - The keypair for the data buffer account
    /// * `digest` - The SHA-256 digest of the TBS (To-Be-Signed) portion of the collateral
    /// * `total_size` - The total size in bytes of the data to be stored
    ///
    /// # Returns
    ///
    /// * `Result<()>` - Success or error
    pub async fn init_data_buffer(
        &self,
        data_buffer_keypair: Keypair,
        digest: [u8; 32],
        total_size: u32,
    ) -> anyhow::Result<()> {
        let data_buffer_pubkey = data_buffer_keypair.pubkey();
        let _tx = self
            .program
            .request()
            .accounts(accounts::InitDataBuffer {
                owner: self.program.payer(),
                data_buffer: data_buffer_pubkey,
                system_program: anchor_client::solana_sdk::system_program::ID,
            })
            .args(args::InitDataBuffer {
                total_size,
                signed_digest: digest,
            })
            .signer(data_buffer_keypair)
            .send()
            .await?;

        Ok(())
    }

    /// Uploads data to a previously initialized data buffer in chunks.
    ///
    /// Because of Solana's transaction size limitations, large data must be split into
    /// smaller chunks and uploaded sequentially.
    ///
    /// # Parameters
    ///
    /// * `data_buffer_pubkey` - The public key of the data buffer account
    /// * `data` - The byte slice containing the data to upload
    /// * `chunk_size` - The size of each chunk in bytes
    ///
    /// # Returns
    ///
    /// * `Result<()>` - Success or error
    pub async fn upload_chunks(
        &self,
        data_buffer_pubkey: Pubkey,
        data: &[u8],
        chunk_size: usize,
    ) -> anyhow::Result<()> {
        for (i, chunk) in data.chunks(chunk_size).enumerate() {
            let offset = i as u32 * chunk_size as u32;
            let chunk_data = chunk.to_vec();

            let _tx = self
                .program
                .request()
                .accounts(accounts::AddDataChunk {
                    owner: self.program.payer(),
                    data_buffer: data_buffer_pubkey,
                })
                .args(args::AddDataChunk { offset, chunk_data })
                .send()
                .await?;
        }
        Ok(())
    }

    /// Loads the data from a data buffer account.
    /// 
    /// # Parameters
    /// * `data_buffer_pubkey` - The public key of the data buffer account
    /// 
    /// # Returns
    /// * `Result<Vec<u8>>` - The data stored in the data buffer
    pub async fn load_buffer_data(&self, data_buffer_pubkey: Pubkey) -> anyhow::Result<Vec<u8>> {
        let data_buffer = self
            .program
            .account::<DataBuffer>(data_buffer_pubkey)
            .await?;

        Ok(data_buffer.data)
    }
}

/// Computes the PDA Pubkey for PCS Collaterals
pub fn compute_pcs_pda_pubkey(ca: CertificateAuthority, is_crl: bool) -> Pubkey {
    let (ret, _) = Pubkey::find_program_address(
        &[b"pcs_cert", ca.common_name().as_bytes(), &[is_crl as u8]],
        &PCCS_PROGRAM_ID,
    );

    ret
}
