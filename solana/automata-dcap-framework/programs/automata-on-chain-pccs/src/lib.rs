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
use programs_shared::crl::*;
use programs_shared::get_cn_from_x509_name;
use types::*;
use utils::zk::digest_ecdsa_zk_verify;

#[program]
pub mod automata_on_chain_pccs {
    use super::*;

    use crate::{
        instructions::UpsertPckCertificate, state::MAX_COLLATERAL_SIZE,
        utils::zk::compute_output_digest,
    };
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
        data_buffer.data = [0; MAX_COLLATERAL_SIZE];
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
        let pck_certificate_account_info = &mut ctx.accounts.pck_certificate.to_account_info();
        let pck_certificate = if pck_certificate_account_info.data_is_empty() {
            // if the account is empty, use load_init to set the account discriminator
            &mut ctx.accounts.pck_certificate.load_init()?
        } else {
            &mut ctx.accounts.pck_certificate.load_mut()?
        };
        let cert_data = ctx.accounts.data_buffer.data.as_slice();

        let (pck_tbs_digest, pck_tbs) = get_certificate_tbs_and_digest(cert_data);

        // We can match digest here for X509 Certificates here as an additional check
        require!(
            pck_tbs_digest == ctx.accounts.data_buffer.signed_digest,
            PccsError::InvalidDigest
        );

        // Check ca_type
        // Extract issuer common name from the certificate
        let pck_issuer_common_name = get_cn_from_x509_name(&pck_tbs.issuer).unwrap();
        let pck_ca_type = CertificateAuthority::from_str(&pck_issuer_common_name)
            .map_err(|_| PccsError::InvalidSubject)?;
        require!(pck_ca_type == ca_type, PccsError::InvalidSubject,);

        // Check if the current PCK Certificate is unexpired
        let (pck_validity_not_before, pck_validity_not_after) = get_certificate_validity(&pck_tbs);
        let now = Clock::get().unwrap().unix_timestamp;
        let pck_is_valid = now >= pck_validity_not_before && now <= pck_validity_not_after;
        if !pck_is_valid {
            return Err(PccsError::ExpiredCollateral.into());
        }

        // Check if the current PCK Certificate has not been revoked
        let pck_crl_data = &ctx.accounts.pck_crl.load()?.cert_data;
        let pck_serial_number = get_certificate_serial(&pck_tbs);
        if check_certificate_revocation(&pck_serial_number, pck_crl_data).is_err() {
            return Err(PccsError::RevokedCertificate.into());
        }

        let issuer_tbs_digest = ctx.accounts.issuer_ca.load()?.digest;

        // Check if the issuer CA is unexpired
        let issuer_is_valid = now >= ctx.accounts.issuer_ca.load()?.validity_not_before
            && now <= ctx.accounts.issuer_ca.load()?.validity_not_after;
        if !issuer_is_valid {
            return Err(PccsError::InvalidIssuer.into());
        }

        // check if the issuer CA has not been revoked
        let root_crl_data = &ctx.accounts.root_crl.load()?.cert_data;
        let issuer_serial_number = ctx.accounts.issuer_ca.load()?.serial_number;
        if check_certificate_revocation(&issuer_serial_number, root_crl_data).is_err() {
            return Err(PccsError::RevokedCertificate.into());
        }

        // Verify the proof
        let fingerprint: [u8; 32] = Sha256::digest(&cert_data).into();
        let output_digest =
            compute_output_digest(&fingerprint, &pck_tbs_digest, &issuer_tbs_digest);

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
        pck_certificate.cert_data = cert_data.try_into().unwrap();
        pck_certificate.digest = pck_tbs_digest;
        pck_certificate.validity_not_before = pck_validity_not_before;
        pck_certificate.validity_not_after = pck_validity_not_after;
        pck_certificate.serial_number = pck_serial_number;

        // Emit event
        emit!(PckCertificateUpserted {
            qe_id: pck_certificate.qe_id,
            pce_id: pck_certificate.pce_id,
            tcbm: pck_certificate.tcbm,
            pda: pck_certificate_account_info.key(),
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
        let root_ca_account_info = &mut ctx.accounts.root_ca.to_account_info();
        let root_ca_pda = if root_ca_account_info.data_is_empty() {
            // if the account is empty, use load_init to set the account discriminator
            &mut ctx.accounts.root_ca.load_init()?
        } else {
            &mut ctx.accounts.root_ca.load_mut()?
        };
        let root_ca_data = ctx.accounts.data_buffer.data.as_slice();

        let (root_tbs_digest, root_tbs) = get_certificate_tbs_and_digest(root_ca_data);

        // We can match digest here for X509 Certificates here as an additional check
        require!(
            root_tbs_digest == ctx.accounts.data_buffer.signed_digest,
            PccsError::InvalidDigest
        );

        // check root ca pubkey matches with hardcoded value
        let root_ca_pubkey = root_tbs.public_key().subject_public_key.as_ref();
        require!(root_ca_pubkey == INTEL_ROOT_PUB_KEY, PccsError::InvalidRoot);

        // Check if the current Root CA Certificate is unexpired
        let (root_ca_validity_not_before, root_ca_validity_not_after) =
            get_certificate_validity(&root_tbs);
        let now = Clock::get().unwrap().unix_timestamp;
        let root_ca_is_valid =
            now >= root_ca_validity_not_before && now <= root_ca_validity_not_after;
        if !root_ca_is_valid {
            return Err(PccsError::ExpiredCollateral.into());
        }

        // verify the proof
        let fingerprint: [u8; 32] = Sha256::digest(&root_ca_data).into();
        let output_digest = compute_output_digest(&fingerprint, &root_tbs_digest, &root_tbs_digest);

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
        root_ca_pda.ca_type = CertificateAuthority::ROOT as u8;
        root_ca_pda.cert_data = root_ca_data.try_into().unwrap();
        root_ca_pda.is_crl = 0;
        root_ca_pda.digest = root_tbs_digest;
        root_ca_pda.validity_not_before = root_ca_validity_not_before;
        root_ca_pda.validity_not_after = root_ca_validity_not_after;
        root_ca_pda.serial_number = get_certificate_serial(&root_tbs);

        // Emit event
        emit!(PcsCertificateUpserted {
            ca_type: CertificateAuthority::ROOT,
            is_crl: false,
            pda: root_ca_account_info.key(),
        });

        Ok(())
    }

    pub fn upsert_root_crl(
        ctx: Context<UpsertRootCrl>,
        zkvm_selector: zk::ZkvmSelector,
        proof: Vec<u8>,
    ) -> Result<()> {
        let root_crl_account_info = &mut ctx.accounts.root_crl.to_account_info();
        let root_crl = if root_crl_account_info.data_is_empty() {
            // if the account is empty, use load_init to set the account discriminator
            &mut ctx.accounts.root_crl.load_init()?
        } else {
            &mut ctx.accounts.root_crl.load_mut()?
        };
        let crl_data = ctx.accounts.data_buffer.data.as_slice();

        let (subject_tbs_digest, subject_tbs) = get_crl_tbs_and_digest(crl_data);

        // We can match digest here for X509 Certificates here as an additional check
        require!(
            subject_tbs_digest == ctx.accounts.data_buffer.signed_digest,
            PccsError::InvalidDigest
        );

        // check if the CA is unexpired (CA certificates are not revoked)
        let (crl_validity_not_before, crl_validity_not_after) = get_crl_validity(&subject_tbs);
        let now = Clock::get().unwrap().unix_timestamp;
        let crl_is_valid = now >= crl_validity_not_before && now <= crl_validity_not_after;
        if !crl_is_valid {
            return Err(PccsError::ExpiredCollateral.into());
        }

        let issuer_tbs_digest = ctx.accounts.root_ca.load()?.digest;

        // Check if the issuer CA is unexpired
        let issuer_is_valid = now >= ctx.accounts.root_ca.load()?.validity_not_before
            && now <= ctx.accounts.root_ca.load()?.validity_not_after;
        if !issuer_is_valid {
            return Err(PccsError::InvalidIssuer.into());
        }

        // verify the proof
        let fingerprint: [u8; 32] = Sha256::digest(&crl_data).into();
        let output_digest =
            compute_output_digest(&fingerprint, &subject_tbs_digest, &issuer_tbs_digest);

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

        root_crl.ca_type = CertificateAuthority::ROOT as u8;
        root_crl.cert_data = crl_data.try_into().unwrap();
        root_crl.is_crl = 1;
        root_crl.digest = subject_tbs_digest;
        root_crl.validity_not_before = crl_validity_not_before;
        root_crl.validity_not_after = crl_validity_not_after;

        // Emit event
        emit!(PcsCertificateUpserted {
            ca_type: CertificateAuthority::ROOT,
            is_crl: true,
            pda: root_crl_account_info.key(),
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
        let pcs_certificate_account_info = &mut ctx.accounts.pcs_certificate.to_account_info();
        let pcs_certificate = if pcs_certificate_account_info.data_is_empty() {
            // if the account is empty, use load_init to set the account discriminator
            &mut ctx.accounts.pcs_certificate.load_init()?
        } else {
            &mut ctx.accounts.pcs_certificate.load_mut()?
        };
        let cert_data = ctx.accounts.data_buffer.data.as_slice();

        let (subject_tbs_digest, subject_tbs) = get_certificate_tbs_and_digest(cert_data);

        // We can match digest here for X509 Certificates here as an additional check
        require!(
            subject_tbs_digest == ctx.accounts.data_buffer.signed_digest,
            PccsError::InvalidDigest
        );

        // check subject common name matches with ca_type
        let subject_common_name = get_cn_from_x509_name(&subject_tbs.subject).unwrap();
        let subject_ca_type = CertificateAuthority::from_str(&subject_common_name)
            .map_err(|_| PccsError::InvalidSubject)?;
        require!(subject_ca_type == ca_type, PccsError::InvalidSubject);

        // check if the CA is unexpired
        let (validity_not_before, validity_not_after) = get_certificate_validity(&subject_tbs);
        let now = Clock::get().unwrap().unix_timestamp;
        let ca_is_valid = now >= validity_not_before && now <= validity_not_after;
        if !ca_is_valid {
            return Err(PccsError::ExpiredCollateral.into());
        }

        // check if the CA has been revoked
        let root_crl_data = &ctx.accounts.root_crl.load()?.cert_data;
        let subject_serial_number = get_certificate_serial(&subject_tbs);
        if check_certificate_revocation(&subject_serial_number, root_crl_data).is_err() {
            return Err(PccsError::RevokedCertificate.into());
        }

        let issuer_tbs_digest = ctx.accounts.issuer_ca.load()?.digest;

        // Check if the issuer CA is unexpired
        let issuer_is_valid = now >= ctx.accounts.issuer_ca.load()?.validity_not_before
            && now <= ctx.accounts.issuer_ca.load()?.validity_not_after;
        if !issuer_is_valid {
            return Err(PccsError::InvalidIssuer.into());
        }

        // verify the proof
        let fingerprint: [u8; 32] = Sha256::digest(&cert_data).into();
        let output_digest =
            compute_output_digest(&fingerprint, &subject_tbs_digest, &issuer_tbs_digest);

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

        pcs_certificate.ca_type = ca_type as u8;
        pcs_certificate.cert_data = cert_data.try_into().unwrap();
        pcs_certificate.is_crl = 0;
        pcs_certificate.digest = subject_tbs_digest;
        pcs_certificate.validity_not_before = validity_not_before;
        pcs_certificate.validity_not_after = validity_not_after;
        pcs_certificate.serial_number = subject_serial_number;

        // Emit event
        emit!(PcsCertificateUpserted {
            ca_type: ca_type,
            is_crl: false,
            pda: pcs_certificate_account_info.key(),
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
        let pcs_crl_account_info = &mut ctx.accounts.pcs_crl.to_account_info();
        let pcs_crl = if pcs_crl_account_info.data_is_empty() {
            // if the account is empty, use load_init to set the account discriminator
            &mut ctx.accounts.pcs_crl.load_init()?
        } else {
            &mut ctx.accounts.pcs_crl.load_mut()?
        };
        let crl_data = ctx.accounts.data_buffer.data.as_slice();

        let (subject_tbs_digest, subject_tbs) = get_crl_tbs_and_digest(crl_data);

        // We cam match digest here for X509 Certificates here as an additional check
        require!(
            subject_tbs_digest == ctx.accounts.data_buffer.signed_digest,
            PccsError::InvalidDigest
        );

        // check if the CA is unexpired (CA certificates are not revoked)
        let (crl_validity_not_before, crl_validity_not_after) = get_crl_validity(&subject_tbs);
        let now = Clock::get().unwrap().unix_timestamp;
        let crl_is_valid = now >= crl_validity_not_before && now <= crl_validity_not_after;
        if !crl_is_valid {
            return Err(PccsError::ExpiredCollateral.into());
        }

        let issuer_tbs_digest = ctx.accounts.issuer_ca.load()?.digest;

        // Check if the issuer CA is unexpired
        let issuer_is_valid = now >= ctx.accounts.issuer_ca.load()?.validity_not_before
            && now <= ctx.accounts.issuer_ca.load()?.validity_not_after;
        if !issuer_is_valid {
            return Err(PccsError::InvalidIssuer.into());
        }

        // check if the issuer CA has not been revoked
        let root_crl_data = &ctx.accounts.root_crl.load()?.cert_data;
        let issuer_serial_number = ctx.accounts.issuer_ca.load()?.serial_number;
        if check_certificate_revocation(&issuer_serial_number, root_crl_data).is_err() {
            return Err(PccsError::RevokedCertificate.into());
        }

        // verify the proof
        let fingerprint: [u8; 32] = Sha256::digest(&crl_data).into();
        let output_digest =
            compute_output_digest(&fingerprint, &subject_tbs_digest, &issuer_tbs_digest);

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

        pcs_crl.ca_type = ca_type as u8;
        pcs_crl.cert_data = crl_data.try_into().unwrap();
        pcs_crl.is_crl = 1;
        pcs_crl.digest = subject_tbs_digest;
        pcs_crl.validity_not_before = crl_validity_not_before;
        pcs_crl.validity_not_after = crl_validity_not_after;

        // Emit event
        emit!(PcsCertificateUpserted {
            ca_type: ca_type,
            is_crl: true,
            pda: pcs_crl_account_info.key(),
        });

        msg!("PCS certificate upserted to {}", ctx.accounts.pcs_crl.key());

        Ok(())
    }

    pub fn upsert_enclave_identity(
        ctx: Context<UpsertEnclaveIdentity>,
        id: EnclaveIdentityType,
        version: u32,
        zkvm_selector: zk::ZkvmSelector,
        proof: Vec<u8>,
    ) -> Result<()> {
        use dcap_rs::types::pod::enclave_identity::zero_copy::*;

        let enclave_identity_account_info = &mut ctx.accounts.enclave_identity.to_account_info();
        let enclave_identity_account = if enclave_identity_account_info.data_is_empty() {
            // if the account is empty, use load_init to set the account discriminator
            &mut ctx.accounts.enclave_identity.load_init()?
        } else {
            &mut ctx.accounts.enclave_identity.load_mut()?
        };
        let data_buffer = &ctx.accounts.data_buffer;

        let identity_digest = data_buffer.signed_digest;
        let identity_data = data_buffer.data.as_slice();

        let identity = EnclaveIdentityZeroCopy::from_bytes(&identity_data[64..])
            .map_err(|_| PccsError::FailedDeserialization)?;

        // Check the given Enclave Identity is unexpired
        let now = Clock::get().unwrap().unix_timestamp;
        let identity_issue_timestamp = identity.issue_date_timestamp();
        let identity_next_update_timestamp = identity.next_update_timestamp();
        let identity_is_valid =
            now >= identity_issue_timestamp && now <= identity_next_update_timestamp;
        if !identity_is_valid {
            return Err(PccsError::ExpiredCollateral.into());
        }

        let issuer_tbs_digest = ctx.accounts.issuer_ca.load()?.digest;

        // Check if the issuer CA is unexpired
        let issuer_is_valid = now >= ctx.accounts.issuer_ca.load()?.validity_not_before
            && now <= ctx.accounts.issuer_ca.load()?.validity_not_after;
        if !issuer_is_valid {
            return Err(PccsError::InvalidIssuer.into());
        }

        // check if the issuer CA has not been revoked
        let root_crl_data = &ctx.accounts.root_crl.load()?.cert_data;
        let issuer_serial_number = ctx.accounts.issuer_ca.load()?.serial_number;
        if check_certificate_revocation(&issuer_serial_number, root_crl_data).is_err() {
            return Err(PccsError::RevokedCertificate.into());
        }

        // verify the proof
        let fingerprint: [u8; 32] = Sha256::digest(identity_data).into();
        let output_digest =
            compute_output_digest(&fingerprint, &identity_digest, &issuer_tbs_digest);

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

        enclave_identity_account.identity_type = id as u8;
        enclave_identity_account.version = version;
        enclave_identity_account.data = identity_data.try_into().unwrap();
        enclave_identity_account.digest = identity_digest;
        enclave_identity_account.issue_timestamp = identity_issue_timestamp;
        enclave_identity_account.next_update_timestamp = identity_next_update_timestamp;

        msg!(
            "Enclave identity  with id: {}, version: {} upserted to {}",
            id.common_name(),
            version,
            enclave_identity_account_info.key()
        );

        emit!(EnclaveIdentityUpserted {
            id,
            version,
            pda: enclave_identity_account_info.key(),
        });

        Ok(())
    }

    pub fn upsert_tcb_info(
        ctx: Context<UpsertTcbInfo>,
        tcb_type: TcbType,
        version: u32,
        fmspc: [u8; 6],
        zkvm_selector: zk::ZkvmSelector,
        proof: Vec<u8>,
    ) -> Result<()> {
        use dcap_rs::types::pod::tcb_info::zero_copy::TcbInfoZeroCopy;

        let tcb_info_account_info = &mut ctx.accounts.tcb_info.to_account_info();
        let tcb_info_account = if tcb_info_account_info.data_is_empty() {
            // if the account is empty, use load_init to set the account discriminator
            &mut ctx.accounts.tcb_info.load_init()?
        } else {
            &mut ctx.accounts.tcb_info.load_mut()?
        };
        let data_buffer = &ctx.accounts.data_buffer;

        let tcb_info_data = data_buffer.data.as_slice();
        let tcb_info_digest = data_buffer.signed_digest;

        // the first 64 bytes is the signature
        let tcb_info = TcbInfoZeroCopy::from_bytes(&tcb_info_data[64..])
            .map_err(|_| PccsError::FailedDeserialization)?;

        // Check the given TCB Info is unexpired
        let tcb_info_issue_timestamp = tcb_info.issue_date_timestamp();
        let tcb_info_next_update_timestamp = tcb_info.next_update_timestamp();
        let now = Clock::get().unwrap().unix_timestamp;
        let tcb_info_is_valid =
            now >= tcb_info_issue_timestamp && now <= tcb_info_next_update_timestamp;
        if !tcb_info_is_valid {
            return Err(PccsError::ExpiredCollateral.into());
        }

        let issuer_tbs_digest = ctx.accounts.issuer_ca.load()?.digest;

        // Check if the issuer CA is unexpired
        let issuer_is_valid = now >= ctx.accounts.issuer_ca.load()?.validity_not_before
            && now <= ctx.accounts.issuer_ca.load()?.validity_not_after;
        if !issuer_is_valid {
            return Err(PccsError::InvalidIssuer.into());
        }

        // check if the issuer CA has not been revoked
        let root_crl_data = &ctx.accounts.root_crl.load()?.cert_data;
        let issuer_serial_number = ctx.accounts.issuer_ca.load()?.serial_number;
        if check_certificate_revocation(&issuer_serial_number, root_crl_data).is_err() {
            return Err(PccsError::RevokedCertificate.into());
        }

        // verify the proof
        let fingerprint: [u8; 32] = Sha256::digest(tcb_info_data).into();
        let output_digest =
            compute_output_digest(&fingerprint, &tcb_info_digest, &issuer_tbs_digest);
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

        tcb_info_account.tcb_type = tcb_type as u8;
        tcb_info_account.version = version;
        tcb_info_account.fmspc = fmspc;
        tcb_info_account.data = tcb_info_data.try_into().unwrap();
        tcb_info_account.digest = tcb_info_digest;
        tcb_info_account.issue_timestamp = tcb_info_issue_timestamp;
        tcb_info_account.next_update_timestamp = tcb_info_next_update_timestamp;

        emit!(TcbInfoUpdated {
            tcb_type,
            version,
            fmspc,
            pda: tcb_info_account_info.key(),
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
