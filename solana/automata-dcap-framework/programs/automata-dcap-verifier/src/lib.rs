#![allow(unexpected_cfgs)]

use anchor_lang::prelude::*;

pub mod errors;
pub mod instructions;
pub mod state;

use errors::*;
use instructions::*;

declare_id!("ASW2HDqoYTJttHbvQMqySgSKZa8dptyRYvU5xoHsTjUB");

#[program]
pub mod automata_dcap_verifier {

    use dcap_rs::types::quote::Quote;

    use super::*;

    pub fn init_quote_buffer(
        ctx: Context<InitQuoteBuffer>,
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
            "Quote buffer initialized with total size: {}, num chunks: {}",
            total_size,
            num_chunks
        );
        Ok(())
    }

    pub fn add_quote_chunk(
        ctx: Context<AddQuoteChunk>,
        chunk_index: u8,
        chunk_data: Vec<u8>,
        offset: u32,
    ) -> Result<()> {
        let data_buffer = &mut ctx.accounts.data_buffer;

        require!(
            data_buffer.owner == *ctx.accounts.owner.key,
            DcapVerifierError::InvalidOwner
        );
        require!(
            !data_buffer.complete,
            DcapVerifierError::BufferAlreadyComplete
        );
        require!(
            chunk_index < data_buffer.num_chunks,
            DcapVerifierError::InvalidChunkIndex
        );
        require!(
            (offset as usize + chunk_data.len()) as u32 <= data_buffer.total_size,
            DcapVerifierError::ChunkOutOfBounds
        );

        let start_index = offset as usize;
        let end_index = start_index + chunk_data.len();

        data_buffer.data[start_index..end_index].copy_from_slice(&chunk_data);
        data_buffer.chunks_received += 1;
        data_buffer.complete = data_buffer.chunks_received >= data_buffer.num_chunks;

        msg!(
            "Added chunk {} with offset {}, total received: {}",
            chunk_index,
            offset,
            data_buffer.chunks_received
        );
        Ok(())
    }

    pub fn verify_dcap_quote(ctx: Context<VerifyDcapQuote>) -> Result<()> {
        let data_buffer = &ctx.accounts.quote_data_buffer;
        let quote_data = &data_buffer.data;

        let quote = Quote::read(&mut &quote_data[..]).map_err(|e| {
            msg!("Error reading quote: {}", e);
            DcapVerifierError::InvalidQuote
        })?;

        msg!("Quote: {:?}", quote);
        Ok(())
    }
}
