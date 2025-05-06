use crate::errors::PccsError;
use crate::state::{DataBuffer, EnclaveIdentity, PckCertificate, PcsCertificate, TcbInfo};
use crate::types::{CertificateAuthority, EnclaveIdentityType, TcbType, zk::ZkvmSelector};

use anchor_lang::prelude::*;

// Maximum size of the certificate data in bytes (4KB)
pub const MAX_CERT_DATA_SIZE: usize = 4096;
pub const TCB_INFO_MAX_SIZE: usize = 8096;

#[derive(Accounts)]
#[instruction(
    total_size: u32,
)]
pub struct InitDataBuffer<'info> {
    /// The signer who will own this quote buffer.
    /// Must sign the transaction and pay for the account creation.
    #[account(mut)]
    pub owner: Signer<'info>,

    /// The account that will store the chunked data.
    #[account(
        init,
        payer = owner,
        space = 8 + 32 + 4 + 1 + 1 + 4 + total_size as usize + 32,
    )]
    pub data_buffer: Account<'info, DataBuffer>,

    /// Required by the system program for account creation.
    pub system_program: Program<'info, System>,
}

/// An instruction to add a chunk of data to the data buffer.
#[derive(Accounts)]
#[instruction(
    chunk_data: Vec<u8>,
    offset: u32,
)]
pub struct AddDataChunk<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,

    #[account(mut)]
    pub data_buffer: Account<'info, DataBuffer>,
}

#[derive(Accounts)]
#[instruction(
    ca_type: CertificateAuthority,
    qe_id: String,
    pce_id: String,
    tcbm: String,
)]
pub struct UpsertPckCertificate<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        init_if_needed,
        payer = authority,
        space = 8 + 1 + 16 + 2 + 18 + MAX_CERT_DATA_SIZE + 32,
        seeds = [
            b"pck_cert",
            &qe_id.as_bytes()[..8],
            &pce_id.as_bytes()[..2],
            &tcbm.as_bytes()[..8],
        ],
        bump,
    )]
    pub pck_certificate: Account<'info, PckCertificate>,

    #[account(
        mut,
        constraint = data_buffer.owner == authority.key() @ PccsError::Unauthorized,
        constraint = data_buffer.complete == true @ PccsError::IncompleteBuffer,
        close = authority
    )]
    pub data_buffer: Account<'info, DataBuffer>,

    #[account(
        constraint = ca_type == CertificateAuthority::PLATFORM || ca_type == CertificateAuthority::PROCESSOR @ PccsError::InvalidSubject,
        seeds = [b"pcs_cert", ca_type.common_name().as_bytes(), &[1]],
        bump,
    )]
    pub pck_crl: Account<'info, PcsCertificate>,

    #[account(
        seeds = [b"pcs_cert", CertificateAuthority::ROOT.common_name().as_bytes(), &[1]],
        bump,
    )]
    pub root_crl: Account<'info, PcsCertificate>,

    #[account(
        constraint = ca_type == CertificateAuthority::PLATFORM || ca_type == CertificateAuthority::PROCESSOR @ PccsError::InvalidSubject,
        seeds = [b"pcs_cert", ca_type.common_name().as_bytes(), &[0]],
        bump,
    )]
    pub issuer_ca: Account<'info, PcsCertificate>,

    /// CHECK: This is the address of the ZKVM Verifier Program.
    pub zkvm_verifier_program: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(
    zkvm_selector: ZkvmSelector,
    proof: Vec<u8>
)]
pub struct UpsertRootCA<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        init_if_needed,
        payer = authority,
        space = 8 + 1 + 1 + MAX_CERT_DATA_SIZE + 32,
        seeds = [b"pcs_cert", CertificateAuthority::ROOT.common_name().as_bytes(), &[0]],
        bump,
    )]
    pub root_ca: Account<'info, PcsCertificate>,

    #[account(
        mut,
        constraint = data_buffer.owner == authority.key() @ PccsError::Unauthorized,
        constraint = data_buffer.complete == true @ PccsError::IncompleteBuffer,
        close = authority
    )]
    pub data_buffer: Account<'info, DataBuffer>,

    /// CHECK: This is the address of the ZKVM Verifier Program.
    pub zkvm_verifier_program: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpsertRootCrl<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        init_if_needed,
        payer = authority,
        space = 8 + 1 + 1 + MAX_CERT_DATA_SIZE + 32,
        seeds = [b"pcs_cert", CertificateAuthority::ROOT.common_name().as_bytes(), &[true as u8]],
        bump,
    )]
    pub root_crl: Account<'info, PcsCertificate>,

    #[account(
        mut,
        constraint = data_buffer.owner == authority.key() @ PccsError::Unauthorized,
        constraint = data_buffer.complete == true @ PccsError::IncompleteBuffer,
        close = authority
    )]
    pub data_buffer: Account<'info, DataBuffer>,

    #[account(
        seeds = [b"pcs_cert", CertificateAuthority::ROOT.common_name().as_bytes(), &[0]],
        bump,
    )]
    pub root_ca: Account<'info, PcsCertificate>,

    /// CHECK: This is the address of the ZKVM Verifier Program.
    pub zkvm_verifier_program: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(ca_type: CertificateAuthority)]
pub struct UpsertPcsCertificate<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        init_if_needed,
        payer = authority,
        space = 8 + 1 + 1 + MAX_CERT_DATA_SIZE + 32,
        seeds = [b"pcs_cert", ca_type.common_name().as_bytes(), &[false as u8]],
        bump,
    )]
    pub pcs_certificate: Account<'info, PcsCertificate>,

    #[account(
        mut,
        constraint = data_buffer.owner == authority.key() @ PccsError::Unauthorized,
        constraint = data_buffer.complete == true @ PccsError::IncompleteBuffer,
        close = authority
    )]
    pub data_buffer: Account<'info, DataBuffer>,

    #[account(
        seeds = [b"pcs_cert", CertificateAuthority::ROOT.common_name().as_bytes(), &[1]],
        bump,
    )]
    pub root_crl: Account<'info, PcsCertificate>,

    #[account(
        constraint = ca_type != CertificateAuthority::ROOT @ PccsError::InvalidSubject,
        seeds = [b"pcs_cert", ca_type.get_issuer(false).common_name().as_bytes(), &[0]],
        bump,
    )]
    pub issuer_ca: Account<'info, PcsCertificate>,

    /// CHECK: This is the address of the ZKVM Verifier Program.
    pub zkvm_verifier_program: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(ca_type: CertificateAuthority)]
pub struct UpsertPcsCrl<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        init_if_needed,
        payer = authority,
        space = 8 + 1 + 1 + MAX_CERT_DATA_SIZE + 32,
        seeds = [b"pcs_cert", ca_type.common_name().as_bytes(), &[true as u8]],
        bump,
    )]
    pub pcs_crl: Account<'info, PcsCertificate>,

    #[account(
        mut,
        constraint = data_buffer.owner == authority.key() @ PccsError::Unauthorized,
        constraint = data_buffer.complete == true @ PccsError::IncompleteBuffer,
        close = authority
    )]
    pub data_buffer: Account<'info, DataBuffer>,

    #[account(
        seeds = [b"pcs_cert", CertificateAuthority::ROOT.common_name().as_bytes(), &[1]],
        bump,
    )]
    pub root_crl: Account<'info, PcsCertificate>,

    #[account(
        constraint = ca_type != CertificateAuthority::ROOT @ PccsError::InvalidSubject,
        seeds = [b"pcs_cert", ca_type.get_issuer(true).common_name().as_bytes(), &[0]],
        bump,
    )]
    pub issuer_ca: Account<'info, PcsCertificate>,

    /// CHECK: This is the address of the ZKVM Verifier Program.
    pub zkvm_verifier_program: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(id: EnclaveIdentityType, version: u8)]
pub struct UpsertEnclaveIdentity<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        init_if_needed,
        payer = authority,
        space = 8 + 1 + MAX_CERT_DATA_SIZE + 32,
        seeds = [b"enclave_identity", id.common_name().as_bytes(), &version.to_le_bytes()[..1]],
        bump,
    )]
    pub enclave_identity: Account<'info, EnclaveIdentity>,

    #[account(
        mut,
        constraint = data_buffer.owner == authority.key() @ PccsError::Unauthorized,
        constraint = data_buffer.complete == true @ PccsError::IncompleteBuffer,
        close = authority
    )]
    pub data_buffer: Account<'info, DataBuffer>,

    #[account(
        seeds = [b"pcs_cert", CertificateAuthority::ROOT.common_name().as_bytes(), &[1]],
        bump,
    )]
    pub root_crl: Account<'info, PcsCertificate>,

    #[account(
        seeds = [b"pcs_cert", CertificateAuthority::SIGNING.common_name().as_bytes(), &[0]],
        bump,
    )]
    pub issuer_ca: Account<'info, PcsCertificate>,

    /// CHECK: This is the address of the ZKVM Verifier Program.
    pub zkvm_verifier_program: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(tcb_type: TcbType, version: u8, fmspc: [u8; 6])]
pub struct UpsertTcbInfo<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        init_if_needed,
        payer = authority,
        space = 8 + 1 + 1 + 6 + TCB_INFO_MAX_SIZE + 32,
        seeds = [b"tcb_info", tcb_type.common_name().as_bytes(), &version.to_le_bytes()[..1], &fmspc],
        bump,
    )]
    pub tcb_info: Account<'info, TcbInfo>,

    #[account(
        mut,
        constraint = data_buffer.owner == authority.key() @ PccsError::Unauthorized,
        constraint = data_buffer.complete == true @ PccsError::IncompleteBuffer,
        close = authority
    )]
    pub data_buffer: Account<'info, DataBuffer>,

    #[account(
        seeds = [b"pcs_cert", CertificateAuthority::ROOT.common_name().as_bytes(), &[1]],
        bump,
    )]
    pub root_crl: Account<'info, PcsCertificate>,

    #[account(
        seeds = [b"pcs_cert", CertificateAuthority::SIGNING.common_name().as_bytes(), &[0]],
        bump,
    )]
    pub issuer_ca: Account<'info, PcsCertificate>,

    /// CHECK: This is the address of the ZKVM Verifier Program.
    pub zkvm_verifier_program: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
}
