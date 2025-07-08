#![allow(unexpected_cfgs)]

use anchor_lang::prelude::*;

pub mod errors;
pub mod event;
pub mod instructions;
pub mod state;
pub mod types;

declare_id!("3Whsu6eycQpQoW2aArtkGcKVbLtosZUuK67PMAc7uqzt");

use errors::PccsError;
use event::*;
use instructions::*;
use programs_shared::certs::*;
use programs_shared::crl::*;
use programs_shared::get_cn_from_x509_name;
use programs_shared::zk::{self, *};
use types::*;

use crate::instructions::UpsertPckCertificate;
use aligned_vec::AVec;
use sha2::{Digest, Sha256};
use std::str::FromStr;

#[program]
pub mod automata_on_chain_pccs {
    use super::*;

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
        zkvm_selector: ZkvmSelector,
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

        let issuer_ca = &ctx.accounts.issuer_ca.load()?;
        let issuer_tbs_digest = issuer_ca.digest;

        // Check if the issuer CA is unexpired
        let issuer_is_valid =
            now >= issuer_ca.validity_not_before && now <= issuer_ca.validity_not_after;
        if !issuer_is_valid {
            return Err(PccsError::InvalidIssuer.into());
        }

        // check if the issuer CA has not been revoked
        let root_crl_data = &ctx.accounts.root_crl.load()?.cert_data;
        let issuer_serial_number = issuer_ca.serial_number;
        if check_certificate_revocation(&issuer_serial_number, root_crl_data).is_err() {
            return Err(PccsError::RevokedCertificate.into());
        }

        // Verify the proof
        let fingerprint: [u8; 32] = Sha256::digest(&cert_data).into();
        validate_zkvm_verifier_account_info(zkvm_selector, &ctx.accounts.zkvm_verifier_program)?;
        let pck_verified_with_zk = ecdsa_zk_verify(
            fingerprint,
            pck_tbs_digest,
            issuer_tbs_digest,
            proof,
            &ctx.accounts.zkvm_verifier_program,
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
        pck_certificate.validity_not_before = pck_validity_not_before;
        pck_certificate.validity_not_after = pck_validity_not_after;
        pck_certificate.serial_number = pck_serial_number;

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
        zkvm_selector: ZkvmSelector,
        proof: Vec<u8>,
    ) -> Result<()> {
        let root_ca_account_info = &mut ctx.accounts.root_ca.to_account_info();
        let root_ca_account_discriminator: [u8; 8] = {
            let data = root_ca_account_info.data.borrow();
            data[..8].try_into().unwrap()
        };
        let root_ca_pda = if account_discriminator_set(root_ca_account_discriminator.as_slice()) {
            &mut ctx.accounts.root_ca.load_mut()?
        } else {
            // if the account is empty, use load_init to set the account discriminator
            &mut ctx.accounts.root_ca.load_init()?
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
        validate_zkvm_verifier_account_info(zkvm_selector, &ctx.accounts.zkvm_verifier_program)?;
        let root_ca_verified_with_zk = ecdsa_zk_verify(
            fingerprint,
            root_tbs_digest,
            root_tbs_digest,
            proof,
            &ctx.accounts.zkvm_verifier_program,
            &ctx.accounts.system_program,
        );

        if root_ca_verified_with_zk.is_err() {
            return Err(PccsError::InvalidProof.into());
        }

        // write to root pda data
        root_ca_pda.ca_type = CertificateAuthority::ROOT as u8;
        root_ca_pda.cert_data_size = root_ca_data.len() as u16;
        root_ca_pda.cert_data[0..root_ca_data.len()].copy_from_slice(root_ca_data);
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
        zkvm_selector: ZkvmSelector,
        proof: Vec<u8>,
    ) -> Result<()> {
        let root_crl_account_info = &mut ctx.accounts.root_crl.to_account_info();
        let root_crl_account_discriminator: [u8; 8] = {
            let data = root_crl_account_info.data.borrow();
            data[..8].try_into().unwrap()
        };
        let root_crl = if account_discriminator_set(root_crl_account_discriminator.as_slice()) {
            &mut ctx.accounts.root_crl.load_mut()?
        } else {
            // if the account is empty, use load_init to set the account discriminator
            &mut ctx.accounts.root_crl.load_init()?
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

        let root_ca = &ctx.accounts.root_ca.load()?;
        let issuer_tbs_digest = root_ca.digest;

        // Check if the issuer CA is unexpired
        let issuer_is_valid =
            now >= root_ca.validity_not_before && now <= root_ca.validity_not_after;
        if !issuer_is_valid {
            return Err(PccsError::InvalidIssuer.into());
        }

        // verify the proof
        let fingerprint: [u8; 32] = Sha256::digest(&crl_data).into();

        validate_zkvm_verifier_account_info(zkvm_selector, &ctx.accounts.zkvm_verifier_program)?;
        let pcs_verified_with_zk = ecdsa_zk_verify(
            fingerprint,
            subject_tbs_digest,
            issuer_tbs_digest,
            proof,
            &ctx.accounts.zkvm_verifier_program,
            &ctx.accounts.system_program,
        );

        if pcs_verified_with_zk.is_err() {
            return Err(PccsError::InvalidProof.into());
        }

        root_crl.ca_type = CertificateAuthority::ROOT as u8;
        root_crl.cert_data_size = crl_data.len() as u16;
        root_crl.cert_data[0..crl_data.len()].copy_from_slice(crl_data);
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
        zkvm_selector: ZkvmSelector,
        proof: Vec<u8>,
    ) -> Result<()> {
        let pcs_certificate_account_info = &mut ctx.accounts.pcs_certificate.to_account_info();
        let pcs_certificate_account_discriminator: [u8; 8] = {
            let data = pcs_certificate_account_info.data.borrow();
            data[..8].try_into().unwrap()
        };
        let pcs_certificate =
            if account_discriminator_set(pcs_certificate_account_discriminator.as_slice()) {
                &mut ctx.accounts.pcs_certificate.load_mut()?
            } else {
                // if the account is empty, use load_init to set the account discriminator
                &mut ctx.accounts.pcs_certificate.load_init()?
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
        let root_crl = &ctx.accounts.root_crl.load()?;
        let root_crl_size = root_crl.cert_data_size as usize;
        let root_crl_data = &root_crl.cert_data[0..root_crl_size];
        let subject_serial_number = get_certificate_serial(&subject_tbs);
        if check_certificate_revocation(&subject_serial_number, root_crl_data).is_err() {
            return Err(PccsError::RevokedCertificate.into());
        }

        let issuer_ca = &ctx.accounts.issuer_ca.load()?;
        let issuer_tbs_digest = issuer_ca.digest;

        // Check if the issuer CA is unexpired
        let issuer_is_valid =
            now >= issuer_ca.validity_not_before && now <= issuer_ca.validity_not_after;
        if !issuer_is_valid {
            return Err(PccsError::InvalidIssuer.into());
        }

        // verify the proof
        let fingerprint: [u8; 32] = Sha256::digest(&cert_data).into();

        validate_zkvm_verifier_account_info(zkvm_selector, &ctx.accounts.zkvm_verifier_program)?;
        let pcs_verified_with_zk = ecdsa_zk_verify(
            fingerprint,
            subject_tbs_digest,
            issuer_tbs_digest,
            proof,
            &ctx.accounts.zkvm_verifier_program,
            &ctx.accounts.system_program,
        );

        if pcs_verified_with_zk.is_err() {
            return Err(PccsError::InvalidProof.into());
        }

        pcs_certificate.ca_type = ca_type as u8;
        pcs_certificate.cert_data_size = cert_data.len() as u16;
        pcs_certificate.cert_data[0..cert_data.len()].copy_from_slice(cert_data);
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
        zkvm_selector: ZkvmSelector,
        proof: Vec<u8>,
    ) -> Result<()> {
        let pcs_crl_account_info = &mut ctx.accounts.pcs_crl.to_account_info();
        let pcs_crl_account_discriminator: [u8; 8] = {
            let data = pcs_crl_account_info.data.borrow();
            data[..8].try_into().unwrap()
        };
        let pcs_crl = if account_discriminator_set(pcs_crl_account_discriminator.as_slice()) {
            &mut ctx.accounts.pcs_crl.load_mut()?
        } else {
            // if the account is empty, use load_init to set the account discriminator
            &mut ctx.accounts.pcs_crl.load_init()?
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

        let issuer_ca = &ctx.accounts.issuer_ca.load()?;
        let issuer_tbs_digest = issuer_ca.digest;

        // Check if the issuer CA is unexpired
        let issuer_is_valid =
            now >= issuer_ca.validity_not_before && now <= issuer_ca.validity_not_after;
        if !issuer_is_valid {
            return Err(PccsError::InvalidIssuer.into());
        }

        // check if the issuer CA has not been revoked
        let root_crl = &ctx.accounts.root_crl.load()?;
        let root_crl_size = root_crl.cert_data_size as usize;
        let root_crl_data = &root_crl.cert_data[0..root_crl_size];
        let issuer_serial_number = issuer_ca.serial_number;
        if check_certificate_revocation(&issuer_serial_number, root_crl_data).is_err() {
            return Err(PccsError::RevokedCertificate.into());
        }

        // verify the proof
        let fingerprint: [u8; 32] = Sha256::digest(&crl_data).into();

        validate_zkvm_verifier_account_info(zkvm_selector, &ctx.accounts.zkvm_verifier_program)?;
        let pcs_verified_with_zk = ecdsa_zk_verify(
            fingerprint,
            subject_tbs_digest,
            issuer_tbs_digest,
            proof,
            &ctx.accounts.zkvm_verifier_program,
            &ctx.accounts.system_program,
        );

        if pcs_verified_with_zk.is_err() {
            return Err(PccsError::InvalidProof.into());
        }

        pcs_crl.ca_type = ca_type as u8;
        pcs_crl.cert_data_size = crl_data.len() as u16;
        pcs_crl.cert_data[0..crl_data.len()].copy_from_slice(crl_data);
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
        version: u8,
        zkvm_selector: ZkvmSelector,
        proof: Vec<u8>,
    ) -> Result<()> {
        use dcap_rs::types::pod::enclave_identity::zero_copy::*;

        let enclave_identity_account = &mut ctx.accounts.enclave_identity;
        let data_buffer = &ctx.accounts.data_buffer;

        let identity_digest = data_buffer.signed_digest;
        let identity_data = data_buffer.data.as_slice();

        // TEMP: Using **owned** data for now by copying and aligned the data into heap,
        // because if I simply "borrow" the data, we would run into alignment issues upon de-serialization
        // AFAIK, the serialized QEIdentity data should not exceed the Solana 32kb heap limit

        let qe_identity_data_owned: Option<AVec<u8>>;
        let identity_data = if identity_data.as_ptr().align_offset(8) == 0 {
            // The data is already aligned, so we can use it directly
            identity_data
        } else {
            // The data is not aligned, so we need to copy it into an aligned vector
            let mut buff: AVec<u8> = AVec::with_capacity(8, identity_data.len());
            buff.extend_from_slice(identity_data);
            qe_identity_data_owned = Some(buff);
            qe_identity_data_owned.as_ref().unwrap().as_slice()
        };

        let identity = EnclaveIdentityZeroCopy::from_bytes(&identity_data[64..]).map_err(|e| {
            msg!("Failed to deserialize enclave identity: {}", e);
            PccsError::FailedDeserialization
        })?;

        // Check the given Enclave Identity is unexpired
        let now = Clock::get().unwrap().unix_timestamp;
        let identity_issue_timestamp = identity.issue_date_timestamp();
        let identity_next_update_timestamp = identity.next_update_timestamp();
        let identity_is_valid =
            now >= identity_issue_timestamp && now <= identity_next_update_timestamp;
        if !identity_is_valid {
            return Err(PccsError::ExpiredCollateral.into());
        }

        let issuer_ca = &ctx.accounts.issuer_ca.load()?;
        let issuer_tbs_digest = issuer_ca.digest;

        // Check if the issuer CA is unexpired
        let issuer_is_valid =
            now >= issuer_ca.validity_not_before && now <= issuer_ca.validity_not_after;
        if !issuer_is_valid {
            return Err(PccsError::InvalidIssuer.into());
        }

        // check if the issuer CA has not been revoked
        let root_crl_data = &ctx.accounts.root_crl.load()?.cert_data;
        let issuer_serial_number = issuer_ca.serial_number;
        if check_certificate_revocation(&issuer_serial_number, root_crl_data).is_err() {
            return Err(PccsError::RevokedCertificate.into());
        }

        // verify the proof
        let fingerprint: [u8; 32] = Sha256::digest(identity_data).into();

        validate_zkvm_verifier_account_info(zkvm_selector, &ctx.accounts.zkvm_verifier_program)?;
        let enclave_identity_verified_with_zk = ecdsa_zk_verify(
            fingerprint,
            identity_digest,
            issuer_tbs_digest,
            proof,
            &ctx.accounts.zkvm_verifier_program,
            &ctx.accounts.system_program,
        );
        if enclave_identity_verified_with_zk.is_err() {
            return Err(PccsError::InvalidProof.into());
        }

        enclave_identity_account.identity_type = id;
        enclave_identity_account.version = version;
        enclave_identity_account.data = identity_data.to_vec();
        enclave_identity_account.digest = identity_digest;
        enclave_identity_account.issue_timestamp = identity_issue_timestamp;
        enclave_identity_account.next_update_timestamp = identity_next_update_timestamp;

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
        zkvm_selector: ZkvmSelector,
        proof: Vec<u8>,
    ) -> Result<()> {
        use dcap_rs::types::pod::tcb_info::zero_copy::TcbInfoZeroCopy;

        let tcb_info_account = &mut ctx.accounts.tcb_info;
        let data_buffer = &ctx.accounts.data_buffer;

        let tcb_info_data = data_buffer.data.as_slice();
        let tcb_info_digest = data_buffer.signed_digest;

        // TEMP: Using **owned** data for now by copying and aligned the data into heap,
        // because if I simply "borrow" the data, we would run into alignment issues upon de-serialization
        // AFAIK, the serialized TCBInfo data should not exceed the Solana 32kb heap limit
        let tcb_info_data_owned: Option<AVec<u8>>;
        let tcb_info_data = if tcb_info_data.as_ptr().align_offset(8) == 0 {
            // The data is already aligned, so we can use it directly
            tcb_info_data
        } else {
            // The data is not aligned, so we need to copy it into an aligned vector
            let mut buff: AVec<u8> = AVec::with_capacity(8, tcb_info_data.len());
            buff.extend_from_slice(tcb_info_data);
            tcb_info_data_owned = Some(buff);
            tcb_info_data_owned.as_ref().unwrap().as_slice()
        };

        // the first 64 bytes is the signature
        let tcb_info = TcbInfoZeroCopy::from_bytes(&tcb_info_data[64..]).map_err(|e| {
            msg!("Failed to deserialize TCB Info: {}", e);
            PccsError::FailedDeserialization
        })?;

        // Check the given TCB Info is unexpired
        let tcb_info_issue_timestamp = tcb_info.issue_date_timestamp();
        let tcb_info_next_update_timestamp = tcb_info.next_update_timestamp();
        let now = Clock::get().unwrap().unix_timestamp;
        let tcb_info_is_valid =
            now >= tcb_info_issue_timestamp && now <= tcb_info_next_update_timestamp;
        if !tcb_info_is_valid {
            return Err(PccsError::ExpiredCollateral.into());
        }

        let issuer_ca = &ctx.accounts.issuer_ca.load()?;
        let issuer_tbs_digest = issuer_ca.digest;

        // Check if the issuer CA is unexpired
        let issuer_is_valid =
            now >= issuer_ca.validity_not_before && now <= issuer_ca.validity_not_after;
        if !issuer_is_valid {
            return Err(PccsError::InvalidIssuer.into());
        }

        // check if the issuer CA has not been revoked
        let root_crl_data = &ctx.accounts.root_crl.load()?.cert_data;
        let issuer_serial_number = issuer_ca.serial_number;
        if check_certificate_revocation(&issuer_serial_number, root_crl_data).is_err() {
            return Err(PccsError::RevokedCertificate.into());
        }

        // verify the proof
        let fingerprint: [u8; 32] = Sha256::digest(tcb_info_data).into();

        validate_zkvm_verifier_account_info(zkvm_selector, &ctx.accounts.zkvm_verifier_program)?;
        let tcb_info_verified_with_zk = ecdsa_zk_verify(
            fingerprint,
            tcb_info_digest,
            issuer_tbs_digest,
            proof,
            &ctx.accounts.zkvm_verifier_program,
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
        tcb_info_account.issue_timestamp = tcb_info_issue_timestamp;
        tcb_info_account.next_update_timestamp = tcb_info_next_update_timestamp;

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

/// Helper function to check if account discriminator has set
fn account_discriminator_set(data: &[u8]) -> bool {
    data.len() == 8 && data.iter().any(|b| *b != 0)
}

/// Helper function to validate the provided zkvm Verifier account info
fn validate_zkvm_verifier_account_info(
    zkvm_selector: ZkvmSelector,
    zkvm_verifier_program: &AccountInfo,
) -> Result<()> {
    match zkvm_selector {
        ZkvmSelector::Succinct => {
            require!(
                *zkvm_verifier_program.key == zk::sp1::ECDSA_SP1_DCAP_P256_PUBKEY,
                PccsError::InvalidZkvmProgram
            );
            Ok(())
        },
        _ => {
            return Err(PccsError::UnsupportedZkvm.into());
        },
    }
}

/// Helper function to perform CPI to the verifier program to verify SNARK proofs
fn ecdsa_zk_verify<'a>(
    fingerprint: [u8; 32],
    subject_tbs_digest: [u8; 32],
    issuer_tbs_digest: [u8; 32],
    proof: Vec<u8>,
    zkvm_verifier_program: &AccountInfo<'a>,
    system_program: &Program<'a, System>,
) -> Result<()> {
    let instruction_data = match zkvm_verifier_program.key {
        &zk::sp1::ECDSA_SP1_DCAP_P256_PUBKEY => {
            use zk::sp1::SP1Groth16Proof;

            let sp1_public_inputs =
                concatenate_output(&fingerprint, &subject_tbs_digest, &issuer_tbs_digest);
            let proof = SP1Groth16Proof {
                proof: proof,
                sp1_public_inputs,
            };

            proof
                .verify_p256_proof_instruction()
                .expect("Failed to create instruction data")
        },
        _ => return Err(PccsError::InvalidZkvmProgram.into()),
    };

    let verify_cpi_context = CpiContext::new(
        zkvm_verifier_program.clone(),
        vec![system_program.to_account_info()],
    );

    use anchor_lang::solana_program::{instruction::Instruction, program::invoke};

    invoke(
        &Instruction {
            program_id: zkvm_verifier_program.key(),
            accounts: verify_cpi_context.to_account_metas(None),
            data: instruction_data,
        },
        &[system_program.to_account_info()],
    )
    .unwrap();

    Ok(())
}
