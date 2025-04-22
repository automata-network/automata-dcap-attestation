use std::ops::Deref;

use anchor_client::{
    Client, Program,
    solana_sdk::{
        compute_budget::ComputeBudgetInstruction,
        signature::Keypair, signer::Signer,
    },
};
use anchor_lang::{declare_program, prelude::Pubkey};
use solana_zk_client::{ID as SOLANA_ZK_PROGRAM_ID, derive_zkvm_verifier_pda};

declare_program!(automata_on_chain_pccs);
use automata_on_chain_pccs::types::ZkvmSelector;
use automata_on_chain_pccs::{client::accounts, client::args};

use crate::{CertificateAuthority, EnclaveIdentityType, TcbType};

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
pub struct PccsClient<S>
{
    program: Program<S>,
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
        total_size: u32,
        num_chunks: u8,
    ) -> anyhow::Result<Pubkey> {
        let quote_buffer_keypair = Keypair::new();
        let quote_buffer_pubkey = quote_buffer_keypair.pubkey();

        let _tx = self
            .program
            .request()
            .accounts(accounts::InitDataBuffer {
                owner: self.program.payer(),
                data_buffer: quote_buffer_pubkey,
                system_program: anchor_client::solana_sdk::system_program::ID,
            })
            .args(args::InitDataBuffer {
                total_size,
            })
            .signer(quote_buffer_keypair)
            .send()
            .await?;

        Ok(quote_buffer_pubkey)
    }

    /// Uploads data to a previously initialized data buffer in chunks.
    ///
    /// Because of Solana's transaction size limitations, large data must be split into
    /// smaller chunks and uploaded sequentially.
    ///
    /// # Arguments
    ///
    /// * `quote_buffer_pubkey` - The public key of the data buffer account
    /// * `data` - The byte slice containing the data to upload
    /// * `chunk_size` - The size of each chunk in bytes
    ///
    /// # Returns
    ///
    /// * `Result<()>` - Success or error
    pub async fn upload_chunks(
        &self,
        quote_buffer_pubkey: Pubkey,
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
                    data_buffer: quote_buffer_pubkey,
                })
                .args(args::AddDataChunk {
                    offset,
                    chunk_data,
                })
                .send()
                .await?;
        }
        Ok(())
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
        qe_id: String,
        pce_id: String,
        tcbm: String,
        data_buffer_pubkey: Pubkey,
    ) -> anyhow::Result<()> {
        let pck_certificate_pda = Pubkey::find_program_address(
            &[
                b"pck_cert",
                &qe_id.as_bytes()[..8],
                &pce_id.as_bytes()[..2],
                &tcbm.as_bytes()[..8],
            ],
            &self.program.id(),
        );
        let _tx = self
            .program
            .request()
            .accounts(accounts::UpsertPckCertificate {
                authority: self.program.payer(),
                pck_certificate: pck_certificate_pda.0,
                data_buffer: data_buffer_pubkey,
                system_program: anchor_client::solana_sdk::system_program::ID,
            })
            .args(args::UpsertPckCertificate {
                qe_id,
                pce_id,
                tcbm,
            })
            .send()
            .await?;
        Ok(())
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
        ca_type: CertificateAuthority,
        is_crl: bool,
        data_buffer_pubkey: Pubkey,
        zkvm_selector: ZkvmSelector,
        zkvm_verifier_program: Pubkey,
    ) -> anyhow::Result<()> {
        let pcs_certificate_pda = Pubkey::find_program_address(
            &[
                b"pcs_cert",
                ca_type.common_name().as_bytes(),
                &[is_crl as u8],
            ],
            &self.program.id(),
        );

        if ca_type == CertificateAuthority::ROOT && !is_crl {
            let data_buffer_account = self
                .program
                .account::<automata_on_chain_pccs::accounts::DataBuffer>(data_buffer_pubkey)
                .await?;
            let root_der = data_buffer_account.data;
            let (_image_id, _journal_bytes, mut groth16_seal) =
                crate::utils::zk::get_x509_ecdsa_verify_proof(
                    root_der.as_slice(),
                    root_der.as_slice(),
                )
                .await?;

            println!("image_id: {:?}", image_id);
            println!("journal_bytes: {:x?}", journal_bytes);

            // negate risczero pi_a
            let mut pi_a: [u8; 64] = [0; 64];
            pi_a.copy_from_slice(&groth16_seal[0..64]);

            let negated_pi_a = crate::utils::negate_g1(&pi_a);
            groth16_seal[0..64].copy_from_slice(&negated_pi_a);

            let (zkvm_verifier_config_pda, _) =
                derive_zkvm_verifier_pda(1u64, &zkvm_verifier_program);

            let _tx = self
                .program
                .request()
                .accounts(accounts::UpsertRootCa {
                    authority: self.program.payer(),
                    root_ca: pcs_certificate_pda.0,
                    data_buffer: data_buffer_pubkey,
                    solana_zk_program: SOLANA_ZK_PROGRAM_ID,
                    zkvm_verifier_config_pda,
                    zkvm_verifier_program,
                    system_program: anchor_client::solana_sdk::system_program::ID,
                })
                .instruction(ComputeBudgetInstruction::set_compute_unit_limit(1_000_000))
                .args(args::UpsertRootCa {
                    zkvm_selector,
                    proof: groth16_seal,
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
                    system_program: anchor_client::solana_sdk::system_program::ID,
                })
                .args(args::UpsertPcsCertificate {
                    ca_type: ca_type.into(),
                    is_crl,
                })
                .send()
                .await?;
        }

        Ok(())
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
        id: EnclaveIdentityType,
        version: u8,
        data_buffer_pubkey: Pubkey,
    ) -> anyhow::Result<()> {
        let enclave_identity_pda = Pubkey::find_program_address(
            &[
                b"enclave_identity",
                id.common_name().as_bytes(),
                &version.to_le_bytes()[..1],
            ],
            &self.program.id(),
        );
        let _tx = self
            .program
            .request()
            .accounts(accounts::UpsertEnclaveIdentity {
                authority: self.program.payer(),
                enclave_identity: enclave_identity_pda.0,
                data_buffer: data_buffer_pubkey,
                system_program: anchor_client::solana_sdk::system_program::ID,
            })
            .args(args::UpsertEnclaveIdentity {
                id: id.into(),
                version,
            })
            .send()
            .await?;
        Ok(())
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
        tcb_type: TcbType,
        version: u8,
        fmspc: [u8; 6],
        data_buffer_pubkey: Pubkey,
    ) -> anyhow::Result<()> {
        let tcb_info_pda = Pubkey::find_program_address(
            &[
                b"tcb_info",
                tcb_type.common_name().as_bytes(),
                &version.to_le_bytes()[..1],
                &fmspc.as_bytes(),
            ],
            &self.program.id(),
        );
        let _tx = self
            .program
            .request()
            .accounts(accounts::UpsertTcbInfo {
                authority: self.program.payer(),
                tcb_info: tcb_info_pda.0,
                data_buffer: data_buffer_pubkey,
                system_program: anchor_client::solana_sdk::system_program::ID,
            })
            .args(args::UpsertTcbInfo {
                tcb_type: tcb_type.into(),
                version,
                fmspc,
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
    ) -> anyhow::Result<automata_on_chain_pccs::accounts::EnclaveIdentity> {
        let enclave_identity_pda = Pubkey::find_program_address(
            &[
                b"enclave_identity",
                id.common_name().as_bytes(),
                &version.to_le_bytes()[..1],
            ],
            &self.program.id(),
        );
        let account = self
            .program
            .account::<automata_on_chain_pccs::accounts::EnclaveIdentity>(enclave_identity_pda.0)
            .await?;
        Ok(account)
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
    ) -> anyhow::Result<automata_on_chain_pccs::accounts::TcbInfo> {
        let tcb_info_pda = Pubkey::find_program_address(
            &[
                b"tcb_info",
                tcb_type.common_name().as_bytes(),
                &version.to_le_bytes()[..1],
                &fmspc.as_bytes(),
            ],
            &self.program.id(),
        );
        let account = self
            .program
            .account::<automata_on_chain_pccs::accounts::TcbInfo>(tcb_info_pda.0)
            .await?;
        Ok(account)
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
    ) -> anyhow::Result<automata_on_chain_pccs::accounts::PckCertificate> {
        let pck_certificate_pda = Pubkey::find_program_address(
            &[
                b"pck_cert",
                &qe_id.as_bytes()[..8],
                &pce_id.as_bytes()[..2],
                &tcbm.as_bytes()[..8],
            ],
            &self.program.id(),
        );
        let account = self
            .program
            .account::<automata_on_chain_pccs::accounts::PckCertificate>(pck_certificate_pda.0)
            .await?;
        Ok(account)
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
    ) -> anyhow::Result<automata_on_chain_pccs::accounts::PcsCertificate> {
        let pcs_certificate_pda = Pubkey::find_program_address(
            &[
                b"pcs_cert",
                ca_type.common_name().as_bytes(),
                &[is_crl as u8],
            ],
            &self.program.id(),
        );
        let account = self
            .program
            .account::<automata_on_chain_pccs::accounts::PcsCertificate>(pcs_certificate_pda.0)
            .await?;
        Ok(account)
    }

    /// Retrieves PCS certificate data directly as a byte vector.
    ///
    /// # Arguments
    ///
    /// * `ca_type` - Certificate Authority type (ROOT, PLATFORM, PROCESSOR, SIGNING)
    /// * `is_crl` - Whether this is a Certificate Revocation List
    ///
    /// # Returns
    ///
    /// * `Result<Vec<u8>>` - The raw certificate data
    pub async fn get_pcs_certificate_data(
        &self,
        ca_type: CertificateAuthority,
        is_crl: bool,
    ) -> anyhow::Result<Vec<u8>> {
        let pcs_certificate = self.get_pcs_certificate(ca_type, is_crl).await?;
        Ok(pcs_certificate.cert_data)
    }

    /// Retrieves TCB info data directly as a byte vector.
    ///
    /// # Arguments
    ///
    /// * `tcb_type` - TCB type (Sgx or Tdx)
    /// * `fmspc` - Family-Model-Stepping-Platform-CustomSKU (FMSPC) value
    /// * `version` - Version number of the TCB info
    ///
    /// # Returns
    ///
    /// * `Result<Vec<u8>>` - The raw TCB info data
    pub async fn get_tcb_info_data(
        &self,
        tcb_type: TcbType,
        fmspc: [u8; 6],
        version: u8,
    ) -> anyhow::Result<Vec<u8>> {
        let tcb_info = self.get_tcb_info(tcb_type, fmspc, version).await?;
        Ok(tcb_info.data)
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
