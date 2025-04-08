use std::ops::Deref;

use anchor_client::{solana_sdk::{commitment_config::CommitmentConfig, signature::Keypair, signer::Signer}, Client, Program};
use anchor_lang::{declare_program, prelude::Pubkey};


declare_program!(automata_on_chain_pccs);
use automata_on_chain_pccs::{client::accounts, client::args};

use crate::{CertificateAuthority, EnclaveIdentityType, TcbType};

pub const PCCS_PROGRAM_ID: Pubkey = automata_on_chain_pccs::ID;


/// A client for the PCCS program.
///
/// It helps to interact with the PCCS program on the Solana blockchain.
pub struct PccsClient<S>
{
    program: Program<S>,
}


impl<S: Clone + Deref<Target = impl Signer>> PccsClient<S> {
    pub fn new(signer: S) -> anyhow::Result<Self> {
        let client = Client::new_with_options(
            anchor_client::Cluster::Localnet,
            signer,
            CommitmentConfig::confirmed(),
        );

        let program = client.program(automata_on_chain_pccs::ID)?;

        Ok(Self { program })
    }

    pub async fn init_data_buffer(&self, total_size: u32, num_chunks: u8) -> anyhow::Result<Pubkey> {
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
                num_chunks,
            })
            .signer(quote_buffer_keypair)
            .send()
            .await?;

        Ok(quote_buffer_pubkey)
    }

    pub async fn upload_chunks(
        &self,
        quote_buffer_pubkey: Pubkey,
        data: &[u8],
        chunk_size: usize,
    ) -> anyhow::Result<()> {

        for (i, chunk) in data.chunks(chunk_size).enumerate() {
            let chunk_index = i as u8;
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
                    chunk_index,
                    offset,
                    chunk_data,
                })
                .send()
                .await?;

        }
        Ok(())
    }


    pub async fn upsert_pck_certificate(
        &self,
        qe_id: String,
        pce_id: String,
        tcbm: String,
        data_buffer_pubkey: Pubkey,
    ) -> anyhow::Result<()> {
        let pck_certificate_pda = Pubkey::find_program_address(
            &[b"pck_cert", &qe_id.as_bytes()[..8], &pce_id.as_bytes()[..2], &tcbm.as_bytes()[..8]],
            &self.program.id()
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

    pub async fn upsert_pcs_certificate(
        &self,
        ca_type: CertificateAuthority,
        is_crl: bool,
        data_buffer_pubkey: Pubkey,
    ) -> anyhow::Result<()> {
        let pcs_certificate_pda = Pubkey::find_program_address(
            &[b"pcs_cert", ca_type.common_name().as_bytes(), &[is_crl as u8]],
            &self.program.id()
        );
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
        Ok(())
    }

    pub async fn upsert_enclave_identity(
        &self,
        id: EnclaveIdentityType,
        version: u8,
        data_buffer_pubkey: Pubkey,
    ) -> anyhow::Result<()> {
        let enclave_identity_pda = Pubkey::find_program_address(
            &[b"enclave_identity", id.common_name().as_bytes(), &version.to_le_bytes()[..1]],
            &self.program.id()
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

    pub async fn upsert_tcb_info(
        &self,
        tcb_type: TcbType,
        version: u8,
        fmspc: String,
        data_buffer_pubkey: Pubkey,
    ) -> anyhow::Result<()> {
        let tcb_info_pda = Pubkey::find_program_address(
            &[b"tcb_info", tcb_type.common_name().as_bytes(), &version.to_le_bytes()[..1], &fmspc.as_bytes()],
            &self.program.id()
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


    pub async fn get_enclave_identity(
        &self,
        id: EnclaveIdentityType,
        version: u8,
    ) -> anyhow::Result<automata_on_chain_pccs::accounts::EnclaveIdentity> {
        let enclave_identity_pda = Pubkey::find_program_address(
            &[b"enclave_identity", id.common_name().as_bytes(), &version.to_le_bytes()[..1]],
            &self.program.id()
        );
        let account = self.program
            .account::<automata_on_chain_pccs::accounts::EnclaveIdentity>(enclave_identity_pda.0).await?;
        Ok(account)
    }

    pub async fn get_tcb_info(
        &self,
        tcb_type: TcbType,
        fmspc: String,
        version: u8,
    ) -> anyhow::Result<automata_on_chain_pccs::accounts::TcbInfo> {
        let tcb_info_pda = Pubkey::find_program_address(
            &[b"tcb_info", tcb_type.common_name().as_bytes(), &version.to_le_bytes()[..1], &fmspc.as_bytes()],
            &self.program.id()
        );
        let account = self.program
            .account::<automata_on_chain_pccs::accounts::TcbInfo>(tcb_info_pda.0).await?;
        Ok(account)
    }

    pub async fn get_pck_certificate(
        &self,
        qe_id: String,
        pce_id: String,
        tcbm: String,
    ) -> anyhow::Result<automata_on_chain_pccs::accounts::PckCertificate> {
        let pck_certificate_pda = Pubkey::find_program_address(
            &[b"pck_cert", &qe_id.as_bytes()[..8], &pce_id.as_bytes()[..2], &tcbm.as_bytes()[..8]],
            &self.program.id()
        );
        let account = self.program
            .account::<automata_on_chain_pccs::accounts::PckCertificate>(pck_certificate_pda.0).await?;
        Ok(account)
    }

    pub async fn get_pcs_certificate(
        &self,
        ca_type: CertificateAuthority,
        is_crl: bool,
    ) -> anyhow::Result<automata_on_chain_pccs::accounts::PcsCertificate> {
        let pcs_certificate_pda = Pubkey::find_program_address(
            &[b"pcs_cert", ca_type.common_name().as_bytes(), &[is_crl as u8]],
            &self.program.id()
        );
        let account = self.program
            .account::<automata_on_chain_pccs::accounts::PcsCertificate>(pcs_certificate_pda.0).await?;
        Ok(account)
    }

    pub async fn get_pcs_certificate_data(
        &self,
        ca_type: CertificateAuthority,
        is_crl: bool,
    ) -> anyhow::Result<Vec<u8>> {
        let pcs_certificate = self.get_pcs_certificate(ca_type, is_crl).await?;
        Ok(pcs_certificate.cert_data)
    }

    pub async fn get_tcb_info_data(
        &self,
        tcb_type: TcbType,
        fmspc: String,
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
            CertificateAuthority::PLATFORM => automata_on_chain_pccs::types::CertificateAuthority::PLATFORM,
            CertificateAuthority::PROCESSOR => automata_on_chain_pccs::types::CertificateAuthority::PROCESSOR,
            CertificateAuthority::SIGNING => automata_on_chain_pccs::types::CertificateAuthority::SIGNING,
        }
    }
}

impl From<automata_on_chain_pccs::types::CertificateAuthority> for CertificateAuthority {
    fn from(ca_type: automata_on_chain_pccs::types::CertificateAuthority) -> Self {
        match ca_type {
            automata_on_chain_pccs::types::CertificateAuthority::ROOT => CertificateAuthority::ROOT,
            automata_on_chain_pccs::types::CertificateAuthority::PLATFORM => CertificateAuthority::PLATFORM,
            automata_on_chain_pccs::types::CertificateAuthority::PROCESSOR => CertificateAuthority::PROCESSOR,
            automata_on_chain_pccs::types::CertificateAuthority::SIGNING => CertificateAuthority::SIGNING,
        }
    }
}
