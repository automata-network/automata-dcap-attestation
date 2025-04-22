#![allow(unexpected_cfgs)]

use anchor_lang::prelude::*;

pub mod errors;
pub mod instructions;
pub mod state;
pub mod event;

declare_id!("3Whsu6eycQpQoW2aArtkGcKVbLtosZUuK67PMAc7uqzt");

use errors::*;
use instructions::*;
use state::*;
use event::*;

#[program]
pub mod automata_on_chain_pccs {
    use crate::{instructions::UpsertPckCertificate, state::CertificateAuthority};

    use super::*;

    pub fn init_data_buffer(
        ctx: Context<InitDataBuffer>,
        total_size: u32,
        num_chunks: u8,
    ) -> Result<()> {
        let data_buffer = &mut ctx.accounts.data_buffer;

        data_buffer.owner = *ctx.accounts.owner.key;
        data_buffer.total_size = total_size;
        data_buffer.num_chunks = num_chunks;
        data_buffer.chunks_received = 0;
        data_buffer.complete = false;
        data_buffer.data = vec![0; total_size as usize];

        msg!(
            "Data buffer initialized with total size: {}, num chunks: {}",
            total_size,
            num_chunks
        );

        Ok(())
    }

    pub fn add_data_chunk(
        ctx: Context<AddDataChunk>,
        chunk_index: u8,
        chunk_data: Vec<u8>,
        offset: u32,
    ) -> Result<()> {
        let data_buffer = &mut ctx.accounts.data_buffer;

        require!(
            data_buffer.owner == *ctx.accounts.owner.key,
            PccsError::InvalidOwner
        );
        require!(!data_buffer.complete, PccsError::BufferAlreadyComplete);
        require!(
            chunk_index < data_buffer.num_chunks,
            PccsError::InvalidChunkIndex
        );
        require!(
            (offset as usize + chunk_data.len()) as u32 <= data_buffer.total_size,
            PccsError::ChunkOutOfBounds
        );

        let start_index = offset as usize;
        let end_index = start_index + chunk_data.len();

        data_buffer.data[start_index..end_index].copy_from_slice(&chunk_data);
        data_buffer.chunks_received += 1;
        data_buffer.complete = data_buffer.chunks_received >= data_buffer.num_chunks;

        msg!(
            "Data chunk added to buffer at offset: {}, total received: {}",
            offset,
            data_buffer.chunks_received
        );

        Ok(())
    }

    pub fn upsert_pck_certificate(
        ctx: Context<UpsertPckCertificate>,
        qe_id: String,
        pce_id: String,
        tcbm: String,
    ) -> Result<()> {
        let pck_certificate = &mut ctx.accounts.pck_certificate;
        let cert_data = ctx.accounts.data_buffer.data.clone();

        pck_certificate.qe_id = hex::decode(qe_id)
            .map_err(|_| PccsError::InvalidHexString)?
            .try_into()
            .map_err(|_| PccsError::InvalidHexString)?;
        pck_certificate.pce_id = hex::decode(pce_id)
            .map_err(|_| PccsError::InvalidHexString)?
            .try_into()
            .map_err(|_| PccsError::InvalidHexString)?;
        pck_certificate.tcbm = hex::decode(tcbm)
            .map_err(|_| PccsError::InvalidHexString)?
            .try_into()
            .map_err(|_| PccsError::InvalidHexString)?;

        pck_certificate.cert_data = cert_data;

        // Emit event
        emit!(PckCertificateUpserted {
            qe_id: pck_certificate.qe_id,
            pce_id: pck_certificate.pce_id,
            tcbm: pck_certificate.tcbm,
            pda: pck_certificate.key(),
        });

        msg!(
            "PCK certificate upserted to {}",
            ctx.accounts.pck_certificate.key()
        );


        Ok(())
    }

    pub fn upsert_pcs_certificate(
        ctx: Context<UpsertPcsCertificate>,
        ca_type: CertificateAuthority,
        is_crl: bool,
    ) -> Result<()> {
        let pcs_certificate = &mut ctx.accounts.pcs_certificate;
        let cert_data = ctx.accounts.data_buffer.data.clone();

        pcs_certificate.ca_type = ca_type;
        pcs_certificate.cert_data = cert_data;
        pcs_certificate.is_crl = is_crl;


        // Emit event
        emit!(PcsCertificateUpserted {
            ca_type: pcs_certificate.ca_type,
            is_crl: pcs_certificate.is_crl,
            pda: pcs_certificate.key(),
        });

        msg!(
            "PCS certificate upserted to {}",
            ctx.accounts.pcs_certificate.key()
        );

        Ok(())
    }

    pub fn upsert_enclave_identity(
        ctx: Context<UpsertEnclaveIdentity>,
        id: EnclaveIdentityType,
        version: u8,
    ) -> Result<()> {
        let enclave_identity = &mut ctx.accounts.enclave_identity;
        let data_buffer = &ctx.accounts.data_buffer;

        enclave_identity.identity_type = id;
        enclave_identity.version = version;
        enclave_identity.data = data_buffer.data.clone();

        msg!(
            "Enclave identity  with id: {}, version: {} upserted to {}",
            id.common_name(),
            version,
            enclave_identity.key()
        );

        emit!(EnclaveIdentityUpserted {
            id: enclave_identity.identity_type,
            version: enclave_identity.version,
            pda: enclave_identity.key(),
        });

        Ok(())
    }

    pub fn upsert_tcb_info(
        ctx: Context<UpsertTcbInfo>,
        tcb_type: TcbType,
        version: u8,
        fmspc: [u8; 6],
    ) -> Result<()> {
        let tcb_info = &mut ctx.accounts.tcb_info;
        let data_buffer = &ctx.accounts.data_buffer;

        tcb_info.tcb_type = tcb_type;
        tcb_info.version = version;
        tcb_info.fmspc = fmspc;
        tcb_info.data = data_buffer.data.clone();

        emit!(TcbInfoUpdated {
            tcb_type: tcb_info.tcb_type,
            version: tcb_info.version,
            fmspc: tcb_info.fmspc,
            pda: tcb_info.key(),
        });

        msg!(
            "TCB info with type: {}, version: {} upserted to {}",
            tcb_type.common_name(),
            version,
            ctx.accounts.tcb_info.key()
        );
        Ok(())
    }
}
