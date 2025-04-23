#![allow(unexpected_cfgs)]

use anchor_lang::prelude::*;

pub mod errors;
pub mod event;
pub mod instructions;
pub mod internal;
pub mod state;
pub mod types;

declare_id!("3Whsu6eycQpQoW2aArtkGcKVbLtosZUuK67PMAc7uqzt");

use errors::*;
use event::*;
use instructions::*;
use internal::certs::INTEL_ROOT_PUB_KEY;
use internal::zk::digest_ecdsa_zk_verify;
use types::*;

#[program]
pub mod automata_on_chain_pccs {
    use super::*;

    use std::str::FromStr;

    use crate::{
        instructions::UpsertPckCertificate,
        internal::certs::{get_certificate_tbs_and_digest, get_cn_from_rdn_sequence},
    };
    use sha2::{Digest, Sha256};

    pub fn init_data_buffer(ctx: Context<InitDataBuffer>, total_size: u32) -> Result<()> {
        let data_buffer = &mut ctx.accounts.data_buffer;

        data_buffer.owner = *ctx.accounts.owner.key;
        data_buffer.total_size = total_size;
        data_buffer.complete = false;
        data_buffer.data = vec![0; total_size as usize];

        msg!("Data buffer initialized with total size: {}", total_size);

        Ok(())
    }

    pub fn add_data_chunk(
        ctx: Context<AddDataChunk>,
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
            (offset as usize + chunk_data.len()) as u32 <= data_buffer.total_size,
            PccsError::ChunkOutOfBounds
        );

        let start_index = offset as usize;
        let end_index = start_index + chunk_data.len();

        data_buffer.data[start_index..end_index].copy_from_slice(&chunk_data);
        data_buffer.complete = offset + chunk_data.len() as u32 == data_buffer.total_size;

        msg!(
            "Data chunk added to buffer at offset: {}, total bytes received until now: {}",
            offset,
            data_buffer.data.len()
        );

        Ok(())
    }

    pub fn upsert_pck_certificate(
        ctx: Context<UpsertPckCertificate>,
        ca_type: CertificateAuthority,
        qe_id: String,
        pce_id: String,
        tcbm: String,
        zkvm_selector: zk::ZkvmSelector,
        proof: Vec<u8>,
    ) -> Result<()> {
        let pck_certificate = &mut ctx.accounts.pck_certificate;
        let cert_data = ctx.accounts.data_buffer.data.clone();

        let (pck_tbs_digest, pck_tbs) = get_certificate_tbs_and_digest(&cert_data);

        // Check ca_type
        // Extract issuer common name from the certificate
        let pck_issuer_common_name = get_cn_from_rdn_sequence(&pck_tbs.issuer).unwrap();
        let pck_ca_type = CertificateAuthority::from_str(&pck_issuer_common_name)
            .map_err(|_| PccsError::InvalidSubject)?;
        require!(pck_ca_type == ca_type, PccsError::InvalidSubject,);

        // TODO: Check if the current PCK Certificate is still valid (unexpired and not revoked)

        let issuer_data = ctx.accounts.issuer_ca.cert_data.clone();
        let (issuer_tbs_digest, _) = get_certificate_tbs_and_digest(&issuer_data);

        // TODO: Check if the issuer CA is unexpired and not revoked

        // Verify the proof
        let mut expected_output: Vec<u8> = Vec::with_capacity(64);
        expected_output.extend_from_slice(&pck_tbs_digest);
        expected_output.extend_from_slice(&issuer_tbs_digest);
        let output_digest: [u8; 32] = Sha256::digest(expected_output.as_slice()).into();

        let pck_verified_with_zk = digest_ecdsa_zk_verify(
            output_digest,
            &proof,
            zkvm_selector,
            &ctx.accounts.zkvm_verifier_program.to_account_info(),
            &ctx.accounts.system_program,
        );

        if pck_verified_with_zk.is_err() {
            return Err(PccsError::InvalidProof.into());
        }

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
        pck_certificate.ca_type = ca_type;
        pck_certificate.cert_data = cert_data;
        pck_certificate.digest = pck_tbs_digest;

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

    pub fn upsert_root_ca(
        ctx: Context<UpsertRootCA>,
        zkvm_selector: zk::ZkvmSelector,
        proof: Vec<u8>,
    ) -> Result<()> {
        let root_ca_pda = &mut ctx.accounts.root_ca;
        let root_ca_data = &ctx.accounts.data_buffer.data;

        let (root_tbs_digest, root_tbs) = get_certificate_tbs_and_digest(&root_ca_data);

        // check root ca pubkey matches with hardcoded value
        let root_ca_pubkey = root_tbs
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .unwrap();
        require!(
            root_ca_pubkey == INTEL_ROOT_PUB_KEY,
            PccsError::InvalidSubject
        );

        // TODO: Check if the current Root CA Certificate is unexpired

        // verify the proof
        let mut expected_output: Vec<u8> = Vec::with_capacity(64);
        expected_output.extend_from_slice(&root_tbs_digest);
        expected_output.extend_from_slice(&root_tbs_digest);
        let output_digest: [u8; 32] = Sha256::digest(expected_output.as_slice()).into();

        let root_ca_verified_with_zk = digest_ecdsa_zk_verify(
            output_digest,
            &proof,
            zkvm_selector,
            &ctx.accounts.zkvm_verifier_program.to_account_info(),
            &ctx.accounts.system_program,
        );

        if root_ca_verified_with_zk.is_err() {
            return Err(PccsError::InvalidProof.into());
        }
        // write to root pda data
        root_ca_pda.ca_type = CertificateAuthority::ROOT;
        root_ca_pda.cert_data = root_ca_data.clone();
        root_ca_pda.is_crl = false;
        root_ca_pda.digest = root_tbs_digest;

        // Emit event
        emit!(PcsCertificateUpserted {
            ca_type: root_ca_pda.ca_type,
            is_crl: root_ca_pda.is_crl,
            pda: root_ca_pda.key(),
        });

        Ok(())
    }

    pub fn upsert_pcs_certificate(
        ctx: Context<UpsertPcsCertificate>,
        ca_type: CertificateAuthority,
        is_crl: bool,
        zkvm_selector: zk::ZkvmSelector,
        proof: Vec<u8>,
    ) -> Result<()> {
        let pcs_certificate = &mut ctx.accounts.pcs_certificate;
        let cert_data = ctx.accounts.data_buffer.data.clone();

        let (subject_tbs_digest, subject_tbs) = get_certificate_tbs_and_digest(&cert_data);

        // check subject common name matches with ca_type
        let subject_common_name = get_cn_from_rdn_sequence(&subject_tbs.subject).unwrap();
        let subject_ca_type = CertificateAuthority::from_str(&subject_common_name)
            .map_err(|_| PccsError::InvalidSubject)?;
        require!(subject_ca_type == ca_type, PccsError::InvalidSubject,);

        // TODO: check if the CA or CRL is unexpired (CA certificates are not revoked)

        let issuer_data = ctx.accounts.issuer_ca.cert_data.clone();
        let (issuer_tbs_digest, _) = get_certificate_tbs_and_digest(&issuer_data);

        // TODO: Check if the issuer CA is unexpired and not revoked

        // verify the proof
        let mut expected_output: Vec<u8> = Vec::with_capacity(64);
        expected_output.extend_from_slice(&subject_tbs_digest);
        expected_output.extend_from_slice(&issuer_tbs_digest);
        let output_digest: [u8; 32] = Sha256::digest(expected_output.as_slice()).into();

        let pcs_verified_with_zk = digest_ecdsa_zk_verify(
            output_digest,
            &proof,
            zkvm_selector,
            &ctx.accounts.zkvm_verifier_program.to_account_info(),
            &ctx.accounts.system_program,
        );

        if pcs_verified_with_zk.is_err() {
            return Err(PccsError::InvalidProof.into());
        }

        pcs_certificate.ca_type = ca_type;
        pcs_certificate.cert_data = cert_data;
        pcs_certificate.is_crl = is_crl;
        pcs_certificate.digest = subject_tbs_digest;

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
        zkvm_selector: zk::ZkvmSelector,
        proof: Vec<u8>,
    ) -> Result<()> {
        let enclave_identity = &mut ctx.accounts.enclave_identity;
        let data_buffer = &ctx.accounts.data_buffer;

        // // TODO: deserializes the data buffer with serde to get Identity and Signature
        // let identity_str: String = todo!();
        // let identity_digest: [u8; 32] = Sha256::digest(identity_str.as_bytes()).into();

        // // TODO: Check the given Enclave Identity is unexpired

        // let issuer_data = ctx.accounts.issuer_ca.cert_data.clone();
        // let (issuer_tbs_digest, _) = get_certificate_tbs_and_digest(&issuer_data);

        // // TODO: Check if the issuer CA is unexpired and not revoked

        // // verify the proof
        // let mut expected_output: Vec<u8> = Vec::with_capacity(64);
        // expected_output.extend_from_slice(&identity_digest);
        // expected_output.extend_from_slice(&issuer_tbs_digest);
        // let output_digest: [u8; 32] = Sha256::digest(expected_output.as_slice()).into();

        // let enclave_identity_verified_with_zk = digest_ecdsa_zk_verify(
        //     output_digest,
        //     &proof,
        //     zkvm_selector,
        //     &ctx.accounts.zkvm_verifier_program.to_account_info(),
        //     &ctx.accounts.system_program,
        // );
        // if enclave_identity_verified_with_zk.is_err() {
        //     return Err(PccsError::InvalidProof.into());
        // }

        enclave_identity.identity_type = id;
        enclave_identity.version = version;
        // TODO: stores Borsh serialized EnclaveIdentity
        enclave_identity.data = data_buffer.data.clone();
        // enclave_identity.digest = identity_digest;

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
        zkvm_selector: zk::ZkvmSelector,
        proof: Vec<u8>,
    ) -> Result<()> {
        let tcb_info = &mut ctx.accounts.tcb_info;
        let data_buffer = &ctx.accounts.data_buffer;

        // // TODO: deserializes the data buffer with serde to get TcbInfo and Signature
        // let tcb_info_str: String = todo!();
        // let tcb_info_digest: [u8; 32] = Sha256::digest(tcb_info_str.as_bytes()).into();

        // // TODO: Check the given TCB Info is unexpired

        // let issuer_data = ctx.accounts.issuer_ca.cert_data.clone();
        // let (issuer_tbs_digest, _) = get_certificate_tbs_and_digest(&issuer_data);

        // // TODO: Check if the issuer CA is unexpired and not revoked

        // // verify the proof
        // let mut expected_output: Vec<u8> = Vec::with_capacity(64);
        // expected_output.extend_from_slice(&tcb_info_digest);
        // expected_output.extend_from_slice(&issuer_tbs_digest);
        // let output_digest: [u8; 32] = Sha256::digest(expected_output.as_slice()).into();
        // let tcb_info_verified_with_zk = digest_ecdsa_zk_verify(
        //     output_digest,
        //     &proof,
        //     zkvm_selector,
        //     &ctx.accounts.zkvm_verifier_program.to_account_info(),
        //     &ctx.accounts.system_program,
        // );
        // if tcb_info_verified_with_zk.is_err() {
        //     return Err(PccsError::InvalidProof.into());
        // }

        tcb_info.tcb_type = tcb_type;
        tcb_info.version = version;
        tcb_info.fmspc = fmspc;
        // TODO: stores Borsh serialized TcbInfo
        tcb_info.data = data_buffer.data.clone();
        // tcb_info.digest = tcb_info_digest;

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
