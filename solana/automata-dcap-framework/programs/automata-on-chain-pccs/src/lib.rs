#![allow(unexpected_cfgs)]

use anchor_lang::prelude::*;

pub mod errors;
pub mod instructions;
pub mod state;

declare_id!("7UuiyphTDFxz4BTBA8MhwwEHVAt4ttREXEhqdRicaVpA");

use errors::*;
use instructions::*;

#[program]
pub mod automata_on_chain_pccs {
    use crate::instructions::UpsertPckCertificate;

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
        require!(
            !data_buffer.complete,
            PccsError::BufferAlreadyComplete
        );
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

        msg!(
            "PCK certificate upserted to {}",
            ctx.accounts.pck_certificate.key()
        );

        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize {}
