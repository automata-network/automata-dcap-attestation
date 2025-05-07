#![allow(unexpected_cfgs)]

use anchor_lang::prelude::*;

pub mod errors;
pub mod event;
pub mod instructions;
pub mod state;
pub mod types;
pub mod utils;

declare_id!("3Whsu6eycQpQoW2aArtkGcKVbLtosZUuK67PMAc7uqzt");

use errors::*;
use event::*;
use instructions::*;
use programs_shared::certs::*;
use programs_shared::clock::*;
use programs_shared::crl::*;
use programs_shared::get_cn_from_rdn_sequence;
use types::*;
use utils::zk::digest_ecdsa_zk_verify;

#[program]
pub mod automata_on_chain_pccs {
    use super::*;

    use crate::instructions::UpsertPckCertificate;
    use sha2::{Digest, Sha256};
    use std::str::FromStr;

    pub fn init_data_buffer(
        ctx: Context<InitDataBuffer>,
        total_size: u32,
        signed_digest: [u8; 32],
    ) -> Result<()> {
        let data_buffer = &mut ctx.accounts.data_buffer;

        data_buffer.owner = *ctx.accounts.owner.key;
        data_buffer.total_size = total_size;
        data_buffer.complete = false;
        data_buffer.data = vec![0; total_size as usize];
        data_buffer.signed_digest = signed_digest;

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
        let cert_data = ctx.accounts.data_buffer.data.as_slice();

        let (pck_tbs_digest, pck_tbs) = get_certificate_tbs_and_digest(cert_data);

        // We can match digest here for X509 Certificates here as an additional check
        require!(
            pck_tbs_digest == ctx.accounts.data_buffer.signed_digest,
            PccsError::InvalidDigest
        );

        // Check ca_type
        // Extract issuer common name from the certificate
        let pck_issuer_common_name = get_cn_from_rdn_sequence(&pck_tbs.issuer).unwrap();
        let pck_ca_type = CertificateAuthority::from_str(&pck_issuer_common_name)
            .map_err(|_| PccsError::InvalidSubject)?;
        require!(pck_ca_type == ca_type, PccsError::InvalidSubject,);

        // Check if the current PCK Certificate is unexpired
        let pck_is_valid = is_certificate_valid(cert_data, Clock::get().unwrap().unix_timestamp);
        if !pck_is_valid {
            return Err(PccsError::ExpiredCollateral.into());
        }

        // Check if the current PCK Certificate has not been revoked
        let pck_crl_data = ctx.accounts.pck_crl.cert_data.as_slice();
        if check_certificate_revocation(cert_data, pck_crl_data).is_err() {
            return Err(PccsError::RevokedCertificate.into());
        }

        let issuer_data = ctx.accounts.issuer_ca.cert_data.as_slice();
        let (issuer_tbs_digest, _) = get_certificate_tbs_and_digest(issuer_data);

        // Check if the issuer CA is unexpired
        let issuer_is_valid =
            is_certificate_valid(issuer_data, Clock::get().unwrap().unix_timestamp);
        if !issuer_is_valid {
            return Err(PccsError::InvalidIssuer.into());
        }

        // Check if the issuer CA has not been revoked
        let root_crl_data = ctx.accounts.root_crl.cert_data.as_slice();
        if check_certificate_revocation(issuer_data, root_crl_data).is_err() {
            return Err(PccsError::RevokedCertificate.into());
        }

        // Verify the proof
        let mut expected_output: Vec<u8> = Vec::with_capacity(96);
        let fingerprint: [u8; 32] = Sha256::digest(&cert_data).into();
        expected_output.extend_from_slice(&fingerprint);
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
        pck_certificate.cert_data = cert_data.to_vec();
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
        let root_ca_data = ctx.accounts.data_buffer.data.as_slice();

        let (root_tbs_digest, root_tbs) = get_certificate_tbs_and_digest(root_ca_data);

        // We can match digest here for X509 Certificates here as an additional check
        require!(
            root_tbs_digest == ctx.accounts.data_buffer.signed_digest,
            PccsError::InvalidDigest
        );

        // check root ca pubkey matches with hardcoded value
        let root_ca_pubkey = root_tbs
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .unwrap();
        require!(root_ca_pubkey == INTEL_ROOT_PUB_KEY, PccsError::InvalidRoot);

        // Check if the current Root CA Certificate is unexpired
        let root_ca_is_valid =
            is_certificate_valid(root_ca_data, Clock::get().unwrap().unix_timestamp);
        if !root_ca_is_valid {
            return Err(PccsError::ExpiredCollateral.into());
        }

        // verify the proof
        let mut expected_output: Vec<u8> = Vec::with_capacity(96);
        let fingerprint: [u8; 32] = Sha256::digest(root_ca_data).into();
        expected_output.extend_from_slice(&fingerprint);
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
        root_ca_pda.cert_data = root_ca_data.to_vec();
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

    pub fn upsert_root_crl(
        ctx: Context<UpsertRootCrl>,
        zkvm_selector: zk::ZkvmSelector,
        proof: Vec<u8>,
    ) -> Result<()> {
        let root_crl = &mut ctx.accounts.root_crl;
        let crl_data = ctx.accounts.data_buffer.data.as_slice();

        let (subject_tbs_digest, _) = get_crl_tbs_and_digest(crl_data);

        // We can match digest here for X509 Certificates here as an additional check
        require!(
            subject_tbs_digest == ctx.accounts.data_buffer.signed_digest,
            PccsError::InvalidDigest
        );

        // check if the CA is unexpired (CA certificates are not revoked)
        let crl_is_valid = is_crl_valid(&crl_data, Clock::get().unwrap().unix_timestamp);
        if !crl_is_valid {
            return Err(PccsError::ExpiredCollateral.into());
        }

        let issuer_data = ctx.accounts.root_ca.cert_data.as_slice();
        let (issuer_tbs_digest, _) = get_certificate_tbs_and_digest(issuer_data);

        // Check if the issuer CA is unexpired
        let issuer_is_valid =
            is_certificate_valid(&issuer_data, Clock::get().unwrap().unix_timestamp);
        if !issuer_is_valid {
            return Err(PccsError::InvalidIssuer.into());
        }

        // verify the proof
        let mut expected_output: Vec<u8> = Vec::with_capacity(96);
        let fingerprint: [u8; 32] = Sha256::digest(&crl_data).into();
        expected_output.extend_from_slice(&fingerprint);
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

        root_crl.ca_type = CertificateAuthority::ROOT;
        root_crl.cert_data = crl_data.to_vec();
        root_crl.is_crl = true;
        root_crl.digest = subject_tbs_digest;

        // Emit event
        emit!(PcsCertificateUpserted {
            ca_type: root_crl.ca_type,
            is_crl: root_crl.is_crl,
            pda: root_crl.key(),
        });

        msg!(
            "PCS certificate upserted to {}",
            ctx.accounts.root_crl.key()
        );

        Ok(())
    }

    pub fn upsert_pcs_certificate(
        ctx: Context<UpsertPcsCertificate>,
        ca_type: CertificateAuthority,
        zkvm_selector: zk::ZkvmSelector,
        proof: Vec<u8>,
    ) -> Result<()> {
        let pcs_certificate = &mut ctx.accounts.pcs_certificate;
        let cert_data = ctx.accounts.data_buffer.data.as_slice();

        let (subject_tbs_digest, subject_tbs) = get_certificate_tbs_and_digest(cert_data);

        // We can match digest here for X509 Certificates here as an additional check
        require!(
            subject_tbs_digest == ctx.accounts.data_buffer.signed_digest,
            PccsError::InvalidDigest
        );

        // check subject common name matches with ca_type
        let subject_common_name = get_cn_from_rdn_sequence(&subject_tbs.subject).unwrap();
        let subject_ca_type = CertificateAuthority::from_str(&subject_common_name)
            .map_err(|_| PccsError::InvalidSubject)?;
        require!(subject_ca_type == ca_type, PccsError::InvalidSubject);

        // check if the CA is unexpired
        let ca_is_valid = is_certificate_valid(cert_data, Clock::get().unwrap().unix_timestamp);
        if !ca_is_valid {
            return Err(PccsError::ExpiredCollateral.into());
        }

        // check if the CA has not been revoked
        let root_crl_data = ctx.accounts.root_crl.cert_data.as_slice();
        if check_certificate_revocation(cert_data, root_crl_data).is_err() {
            return Err(PccsError::RevokedCertificate.into());
        }

        let issuer_data = ctx.accounts.issuer_ca.cert_data.as_slice();
        let (issuer_tbs_digest, _) = get_certificate_tbs_and_digest(issuer_data);

        // Check if the issuer CA is unexpired
        let issuer_is_valid =
            is_certificate_valid(issuer_data, Clock::get().unwrap().unix_timestamp);
        if !issuer_is_valid {
            return Err(PccsError::InvalidIssuer.into());
        }

        // verify the proof
        let mut expected_output: Vec<u8> = Vec::with_capacity(96);
        let fingerprint: [u8; 32] = Sha256::digest(&cert_data).into();
        expected_output.extend_from_slice(&fingerprint);
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
        pcs_certificate.cert_data = cert_data.to_vec();
        pcs_certificate.is_crl = false;
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

    pub fn upsert_pcs_crl(
        ctx: Context<UpsertPcsCrl>,
        ca_type: CertificateAuthority,
        zkvm_selector: zk::ZkvmSelector,
        proof: Vec<u8>,
    ) -> Result<()> {
        let pcs_crl = &mut ctx.accounts.pcs_crl;
        let crl_data = ctx.accounts.data_buffer.data.as_slice();

        let (subject_tbs_digest, subject_tbs) = get_crl_tbs_and_digest(crl_data);

        // We can match digest here for X509 Certificates here as an additional check
        require!(
            subject_tbs_digest == ctx.accounts.data_buffer.signed_digest,
            PccsError::InvalidDigest
        );

        // check issuer common name matches with ca_type
        let common_name_found = get_cn_from_rdn_sequence(&subject_tbs.issuer).unwrap();
        let expected_ca_type = CertificateAuthority::from_str(&common_name_found)
            .map_err(|_| PccsError::InvalidSubject)?;
        require!(expected_ca_type == ca_type, PccsError::InvalidSubject);

        // check if the CA is unexpired (CA certificates are not revoked)
        let crl_is_valid = is_crl_valid(&crl_data, Clock::get().unwrap().unix_timestamp);
        if !crl_is_valid {
            return Err(PccsError::ExpiredCollateral.into());
        }

        let issuer_data = ctx.accounts.issuer_ca.cert_data.as_slice();
        let (issuer_tbs_digest, _) = get_certificate_tbs_and_digest(issuer_data);

        // Check if the issuer CA is unexpired
        let issuer_is_valid =
            is_certificate_valid(&issuer_data, Clock::get().unwrap().unix_timestamp);
        if !issuer_is_valid {
            return Err(PccsError::InvalidIssuer.into());
        }

        // check if the issuer CA has not been revoked
        let root_crl_data = ctx.accounts.root_crl.cert_data.as_slice();
        if check_certificate_revocation(issuer_data, root_crl_data).is_err() {
            return Err(PccsError::RevokedCertificate.into());
        }

        // verify the proof
        let mut expected_output: Vec<u8> = Vec::with_capacity(96);
        let fingerprint: [u8; 32] = Sha256::digest(&crl_data).into();
        expected_output.extend_from_slice(&fingerprint);
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

        pcs_crl.ca_type = ca_type;
        pcs_crl.cert_data = crl_data.to_vec();
        pcs_crl.is_crl = true;
        pcs_crl.digest = subject_tbs_digest;

        // Emit event
        emit!(PcsCertificateUpserted {
            ca_type: pcs_crl.ca_type,
            is_crl: pcs_crl.is_crl,
            pda: pcs_crl.key(),
        });

        msg!("PCS certificate upserted to {}", ctx.accounts.pcs_crl.key());

        Ok(())
    }

    pub fn upsert_enclave_identity(
        ctx: Context<UpsertEnclaveIdentity>,
        id: EnclaveIdentityType,
        version: u8,
        zkvm_selector: zk::ZkvmSelector,
        proof: Vec<u8>,
    ) -> Result<()> {
        let enclave_identity_account = &mut ctx.accounts.enclave_identity;
        let data_buffer = &ctx.accounts.data_buffer;

        let identity_digest = data_buffer.signed_digest;
        let identity_data = data_buffer.data.as_slice();

        // Check the given Enclave Identity is unexpired
        use dcap_rs::types::enclave_identity::EnclaveIdentity;
        let identity = EnclaveIdentity::from_borsh_bytes(identity_data)
            .map_err(|_| PccsError::FailedDeserialization)?;
        let identity_is_valid = is_collateral_valid(
            identity.issue_date.timestamp(),
            identity.next_update.timestamp(),
            Clock::get().unwrap().unix_timestamp,
        );
        if !identity_is_valid {
            return Err(PccsError::ExpiredCollateral.into());
        }

        let issuer_data = ctx.accounts.issuer_ca.cert_data.as_slice();
        let (issuer_tbs_digest, _) = get_certificate_tbs_and_digest(issuer_data);

        // Check if the issuer CA is unexpired
        let issuer_is_valid =
            is_certificate_valid(issuer_data, Clock::get().unwrap().unix_timestamp);
        if !issuer_is_valid {
            return Err(PccsError::InvalidIssuer.into());
        }

        // Check if the issuer CA has not been revoked
        let root_crl_data = ctx.accounts.root_crl.cert_data.as_slice();
        if check_certificate_revocation(issuer_data, root_crl_data).is_err() {
            return Err(PccsError::RevokedCertificate.into());
        }

        // verify the proof
        let mut expected_output: Vec<u8> = Vec::with_capacity(96);
        let fingerprint: [u8; 32] = Sha256::digest(identity_data).into();
        expected_output.extend_from_slice(&fingerprint);
        expected_output.extend_from_slice(&identity_digest);
        expected_output.extend_from_slice(&issuer_tbs_digest);
        let output_digest: [u8; 32] = Sha256::digest(expected_output.as_slice()).into();

        let enclave_identity_verified_with_zk = digest_ecdsa_zk_verify(
            output_digest,
            &proof,
            zkvm_selector,
            &ctx.accounts.zkvm_verifier_program.to_account_info(),
            &ctx.accounts.system_program,
        );
        if enclave_identity_verified_with_zk.is_err() {
            return Err(PccsError::InvalidProof.into());
        }

        enclave_identity_account.identity_type = id;
        enclave_identity_account.version = version;
        enclave_identity_account.data = identity_data.to_vec();
        enclave_identity_account.digest = identity_digest;

        msg!(
            "Enclave identity  with id: {}, version: {} upserted to {}",
            id.common_name(),
            version,
            enclave_identity_account.key()
        );

        emit!(EnclaveIdentityUpserted {
            id: enclave_identity_account.identity_type,
            version: enclave_identity_account.version,
            pda: enclave_identity_account.key(),
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
        let tcb_info_account = &mut ctx.accounts.tcb_info;
        let data_buffer = &ctx.accounts.data_buffer;

        let tcb_info_data = data_buffer.data.as_slice();
        let tcb_info_digest = data_buffer.signed_digest;

        // Check the given TCB Info is unexpired
        use dcap_rs::types::tcb_info::TcbInfo;
        let tcb_info = TcbInfo::from_borsh_bytes(tcb_info_data)
            .map_err(|_| PccsError::FailedDeserialization)?;
        let tcb_info_is_valid = is_collateral_valid(
            tcb_info.issue_date.timestamp(),
            tcb_info.next_update.timestamp(),
            Clock::get().unwrap().unix_timestamp,
        );
        if !tcb_info_is_valid {
            return Err(PccsError::ExpiredCollateral.into());
        }

        let issuer_data = ctx.accounts.issuer_ca.cert_data.as_slice();
        let (issuer_tbs_digest, _) = get_certificate_tbs_and_digest(issuer_data);

        // Check if the issuer CA is unexpired
        let issuer_is_valid =
            is_certificate_valid(issuer_data, Clock::get().unwrap().unix_timestamp);
        if !issuer_is_valid {
            return Err(PccsError::InvalidIssuer.into());
        }

        // Check if the issuer CA has not been revoked
        let root_crl_data = ctx.accounts.root_crl.cert_data.as_slice();
        if check_certificate_revocation(issuer_data, root_crl_data).is_err() {
            return Err(PccsError::RevokedCertificate.into());
        }

        // verify the proof
        let mut expected_output: Vec<u8> = Vec::with_capacity(96);
        let fingerprint: [u8; 32] = Sha256::digest(tcb_info_data).into();
        expected_output.extend_from_slice(&fingerprint);
        expected_output.extend_from_slice(&tcb_info_digest);
        expected_output.extend_from_slice(&issuer_tbs_digest);
        let output_digest: [u8; 32] = Sha256::digest(expected_output.as_slice()).into();
        let tcb_info_verified_with_zk = digest_ecdsa_zk_verify(
            output_digest,
            &proof,
            zkvm_selector,
            &ctx.accounts.zkvm_verifier_program.to_account_info(),
            &ctx.accounts.system_program,
        );
        if tcb_info_verified_with_zk.is_err() {
            return Err(PccsError::InvalidProof.into());
        }

        tcb_info_account.tcb_type = tcb_type;
        tcb_info_account.version = version;
        tcb_info_account.fmspc = fmspc;
        tcb_info_account.data = tcb_info_data.to_vec();
        tcb_info_account.digest = tcb_info_digest;

        emit!(TcbInfoUpdated {
            tcb_type: tcb_info_account.tcb_type,
            version: tcb_info_account.version,
            fmspc: tcb_info_account.fmspc,
            pda: tcb_info_account.key(),
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
