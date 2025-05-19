pub mod enclave_identity_dao;
pub mod fmspc_tcb_dao;
pub mod pck_dao;
pub mod pcs_dao;
pub mod utils;

use std::ops::Deref;

use crate::shared::negate_g1;
use anchor_client::{
    Client, Program,
    solana_sdk::signer::{Signer, keypair::Keypair},
};
use anchor_lang::{declare_program, prelude::Pubkey};
use utils::zk::*;

pub use ecdsa_secp256r1_host::InputType as EcdsaZkVerifyInputType;

declare_program!(automata_on_chain_pccs);
use automata_on_chain_pccs::{client::accounts, client::args};
use automata_on_chain_pccs::accounts::DataBuffer;

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

    /// Initializes a new data buffer account on-chain for storing certificates or other attestation data.
    ///
    /// This method creates a new Solana account that will be used to store data in chunks.
    ///
    /// # Arguments
    ///
    /// * `total_size` - The total size in bytes of the data to be stored
    ///
    /// # Returns
    ///
    /// * `Result<Pubkey>` - The public key of the created data buffer account
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
    /// # Arguments
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

    pub async fn load_buffer_data(
        &self,
        data_buffer_pubkey: Pubkey,
    ) -> anyhow::Result<Vec<u8>> {
        let data_buffer = self
            .program
            .account::<DataBuffer>(data_buffer_pubkey)
            .await?;

        Ok(data_buffer.data)
    }

}

pub async fn request_ecdsa_verify_proof(
    input_type: EcdsaZkVerifyInputType,
    input_data: &[u8],
    issuer_der: &[u8]
) -> anyhow::Result<(
    [u8; 32], // image_id
    Vec<u8>,  // journal_bytes
    Vec<u8>,  // Groth16 Seal
)> {
    let (image_id, journal, mut seal) =
        get_ecdsa_verify_proof(input_type, input_data, issuer_der).await?;

    // negate risczero pi_a
    let mut pi_a: [u8; 64] = [0; 64];
    pi_a.copy_from_slice(&seal[0..64]);

    let negated_pi_a = negate_g1(&pi_a);
    seal[0..64].copy_from_slice(&negated_pi_a);

    println!("seal: {}", hex::encode(&seal));

    Ok((image_id, journal, seal))
}
