//! Intel SGX/TDX DCAP attestation verification library.
//!
//! This crate provides a pure Rust implementation of Intel's Data Center Attestation
//! Primitives (DCAP) for verifying SGX and TDX attestation quotes. It performs
//! comprehensive verification including certificate chain validation, signature
//! verification, TCB status checking, and collateral expiration checks.
//!
//! # Features
//!
//! - `full` - Enable full verification functionality (default)
//!
//! # Example
//!
//! ```ignore
//! use dcap_rs::{verify_dcap_quote, types::{quote::Quote, collateral::Collateral}};
//! use std::time::SystemTime;
//!
//! let quote_bytes = vec![/* ... */];
//! let mut reader = quote_bytes.as_slice();
//! let quote = Quote::read(&mut reader)?;
//!
//! let collateral = Collateral::new(
//!     root_ca_crl_der,
//!     pck_crl_der,
//!     tcb_info_and_qe_identity_issuer_chain_pem_bytes,
//!     tcb_info_json_str,
//!     qe_identity_json_str
//! )?;
//!
//! let verified = verify_dcap_quote(SystemTime::now(), collateral, quote)?;
//! ```

/// TDX-specific verification logic (feature-gated).
#[cfg(feature = "full")]
pub mod tdx;
/// Certificate trust store and chain validation.
pub mod trust_store;
/// Type definitions for quotes, collaterals, and verification outputs.
pub mod types;
/// Utility functions for expiration checking and data handling.
pub mod utils;

#[cfg(feature = "full")]
use anyhow::{Context, anyhow, bail};
#[cfg(feature = "full")]
use chrono::{DateTime, Utc};
#[cfg(feature = "full")]
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
#[cfg(feature = "full")]
use std::time::SystemTime;
#[cfg(feature = "full")]
use tdx::*;
#[cfg(feature = "full")]
use trust_store::{TrustStore, TrustedIdentity};
#[cfg(feature = "full")]
use types::{
    VerifiedOutput,
    collateral::Collateral,
    enclave_identity::QeTcbStatus,
    quote::{AttestationKeyType, Quote, TDX_TEE_TYPE},
    sgx_x509::SgxPckExtension,
    tcb_info::{TcbInfo, TcbStatus},
};
#[cfg(feature = "full")]
use utils::Expireable;
#[cfg(feature = "full")]
use x509_cert::der::{Any, DecodePem};
#[cfg(feature = "full")]
use x509_verify::VerifyingKey as X509VerifyingKey;
#[cfg(feature = "full")]
use zerocopy::AsBytes;

/// Intel SGX Root CA public key in PEM format.
///
/// This is the trusted root of the Intel SGX certificate chain used to verify
/// all SGX/TDX attestation quotes.
pub const INTEL_ROOT_CA_PEM: &str = "\
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi71OiO
SLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlA==
-----END PUBLIC KEY-----";

/// Verifies an SGX or TDX DCAP quote with provided collaterals.
///
/// This is the main entry point for quote verification. It performs the complete
/// DCAP verification flow as specified by Intel, including:
///
/// 1. Certificate chain integrity verification (from quote to Intel root CA)
/// 2. Quoting Enclave identity and signature verification
/// 3. Platform TCB status checking
/// 4. TDX Module verification (for TDX quotes)
/// 5. TCB status convergence
///
/// # Arguments
///
/// * `current_time` - Reference time for certificate and collateral expiration checks
/// * `collateral` - Attestation collaterals (certificates, CRLs, TCB info, QE identity)
/// * `quote` - The parsed attestation quote to verify
///
/// # Returns
///
/// Returns [`VerifiedOutput`] containing the quote body and final TCB status.
///
/// # Errors
///
/// Returns an error if any verification step fails, including:
/// - Expired certificates or collaterals
/// - Invalid signatures
/// - Revoked TCB or Quoting Enclave
/// - Certificate chain validation failures
/// - TCB/QE identity mismatches
#[cfg(feature = "full")]
pub fn verify_dcap_quote(
    current_time: SystemTime,
    collateral: Collateral,
    quote: Quote,
) -> anyhow::Result<VerifiedOutput> {
    // 1. Verify the integrity of the signature chain from the Quote to the Intel-issued PCK
    //    certificate, and that no keys in the chain have been revoked.
    use crate::types::quote::QuoteBody;
    let tcb_info = verify_integrity(current_time, &collateral, &quote)?;

    // 2. Verify the Quoting Enclave source and all signatures in the Quote.
    let qe_tcb_status = verify_quote(current_time, &collateral, &quote)?;

    assert!(
        qe_tcb_status != QeTcbStatus::Revoked,
        "Quoting Enclave TCB Revoked"
    );

    // 3. Verify the status of Intel SGX TCB described in the chain.
    let pck_extension = quote.signature.get_pck_extension()?;
    let (sgx_tcb_status, tdx_tcb_status, advisory_ids) =
        verify_tcb_status(&tcb_info, &pck_extension, &quote)?;

    assert!(
        sgx_tcb_status != TcbStatus::Revoked || tdx_tcb_status != TcbStatus::Revoked,
        "FMPSC TCB Revoked"
    );

    let advisory_ids = if advisory_ids.is_empty() {
        None
    } else {
        Some(advisory_ids)
    };

    // 4. If TDX type then verify the status of TDX Module status and converge and send
    let mut tcb_status;
    if quote.header.tee_type == TDX_TEE_TYPE {
        tcb_status = tdx_tcb_status;
        let tdx_module_tcb_status =
            verify_tdx_module(&tcb_info, quote.body.as_tdx_report_body().unwrap())?;
        tcb_status =
            TcbInfo::converge_tcb_status_with_tdx_module(tcb_status, tdx_module_tcb_status);

        if let QuoteBody::Td15QuoteBody(td_report) = &quote.body {
            let (relaunch_needed, configuration_needed) = check_for_relaunch(
                &tcb_info,
                td_report,
                qe_tcb_status,
                sgx_tcb_status,
                tdx_tcb_status,
                tdx_module_tcb_status,
            );
            if relaunch_needed {
                if configuration_needed {
                    tcb_status = TcbStatus::RelaunchAdvisedConfigurationNeeded;
                } else {
                    tcb_status = TcbStatus::RelaunchAdvised;
                }
            }
        }
    } else {
        tcb_status = sgx_tcb_status;
    }

    // 5. Converge platform TCB status with QE TCB status
    tcb_status = TcbInfo::converge_tcb_status_with_qe_tcb(tcb_status, qe_tcb_status.into());

    Ok(VerifiedOutput {
        quote_version: quote.header.version.get(),
        quote_body_type: quote.body_type,
        tcb_status: tcb_status as u8,
        fmspc: pck_extension.fmspc,
        quote_body: quote.body,
        advisory_ids,
    })
}

#[cfg(feature = "full")]
fn verify_integrity(
    current_time: SystemTime,
    collateral: &Collateral,
    quote: &Quote,
) -> anyhow::Result<types::tcb_info::TcbInfo> {
    if !collateral
        .tcb_info_and_qe_identity_issuer_chain
        .valid_at(current_time)
    {
        bail!("expired tcb info issuer chain");
    }
    let pck_cert_chain_data = quote.signature.get_pck_cert_chain()?;

    if !pck_cert_chain_data.pck_cert_chain.valid_at(current_time) {
        bail!("expired pck cert chain");
    }

    let root_ca = collateral
        .tcb_info_and_qe_identity_issuer_chain
        .last()
        .context("tcb issuer chain is empty")?;

    // Verify the root certificate is self issued
    if root_ca.tbs_certificate.issuer != root_ca.tbs_certificate.subject {
        bail!("root certificate is not self issued");
    }

    let spki = x509_cert::spki::SubjectPublicKeyInfo::<Any, _>::from_pem(INTEL_ROOT_CA_PEM)?;
    let intel_root_ca = X509VerifyingKey::try_from(spki).unwrap();
    intel_root_ca
        .verify(root_ca)
        .context("Root CA signature verification failed")?;

    // Build initial trust store with the root certificate
    let mut trust_store = TrustStore::new(current_time, vec![root_ca.clone()])?;

    // Verify that the CRL is signed by Intel and add it to the store.
    trust_store
        .add_crl(collateral.root_ca_crl.clone(), true, None)
        .context("failed to verify root ca crl")?;

    // Build intermediaries from the PCK cert chain, EXCLUDING the leaf certificate
    let mut intermediaries = std::collections::BTreeMap::new();
    // Skip the first certificate (leaf) and only use intermediates and root
    for cert in pck_cert_chain_data.pck_cert_chain.iter().skip(1) {
        let subject = cert.tbs_certificate.subject.to_string();
        let pk = cert
            .try_into()
            .map_err(|e| anyhow::anyhow!("failed to decode key from certificate: {}", e))?;

        intermediaries.insert(
            subject,
            TrustedIdentity {
                cert: cert.clone(), //TODO: remove clone eventually, or else may hit solana limits
                pk,
            },
        );
    }

    trust_store
        .add_crl(collateral.pck_crl.clone(), true, Some(&intermediaries))
        .context("failed to verify pck crl")?;

    // Verify PCK Cert Chain and add it to the store.
    let pck_cert_chain_data = quote.signature.get_pck_cert_chain()?;
    trust_store
        .verify_chain_leaf(&pck_cert_chain_data.pck_cert_chain)
        .context("failed to verify pck crl issuer chain")?;

    // Verify TCB Info Issuer Chain
    let tcb_issuer = trust_store
        .verify_chain_leaf(&collateral.tcb_info_and_qe_identity_issuer_chain)
        .context("failed to verify tcb info issuer chain")?;

    // Get TCB Signer Public Key
    let tcb_signer = tcb_issuer
        .cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .context("missing tcb signer public key")?;

    // We are making big assumption here that the key is ECDSA P-256
    let tcb_signer = p256::ecdsa::VerifyingKey::from_sec1_bytes(tcb_signer)
        .context("invalid tcb signer public key")?;

    // Verify the TCB Info
    let tcb_info = collateral
        .tcb_info
        .as_tcb_info_and_verify(current_time, tcb_signer)
        .context("failed to verify tcb info signature")?;

    // Verify the quote identity issuer chain
    let _qe_id_issuer = trust_store
        .verify_chain_leaf(&collateral.tcb_info_and_qe_identity_issuer_chain)
        .context("failed to verify pck crl issuer certificate chain")?;

    Ok(tcb_info)
}

#[cfg(feature = "full")]
fn verify_quote(
    current_time: SystemTime,
    collateral: &Collateral,
    quote: &Quote,
) -> anyhow::Result<QeTcbStatus> {
    let qe_tcb_status = verify_quote_enclave_source(current_time, collateral, quote)?;
    verify_quote_signatures(quote)?;
    Ok(qe_tcb_status)
}

/// Verify the quote enclave source and return the TCB status
/// of the quoting enclave.
#[cfg(feature = "full")]
pub fn verify_quote_enclave_source(
    current_time: SystemTime,
    collateral: &Collateral,
    quote: &Quote,
) -> anyhow::Result<QeTcbStatus> {
    // Verify that the enclave identity root is signed by root certificate
    let qe_identity = collateral
        .qe_identity
        .validate_as_enclave_identity(
            &VerifyingKey::from_sec1_bytes(
                collateral.tcb_info_and_qe_identity_issuer_chain[0]
                    .tbs_certificate
                    .subject_public_key_info
                    .subject_public_key
                    .as_bytes()
                    .context("missing qe identity public key")?,
            )
            .context("failed to verify quote enclave identity")?,
        )
        .context("failed to verify quote enclave identity")?;

    // Validate that current time is between issue_date and next_update
    let current_time: DateTime<Utc> = current_time.into();
    if current_time < qe_identity.issue_date || current_time > qe_identity.next_update {
        bail!("tcb info is not valid at current time");
    }

    // Compare the mr_signer values
    let qe_identity_mr_signer_bytes: [u8; 32] = qe_identity.mrsigner_bytes();
    if qe_identity_mr_signer_bytes != quote.signature.qe_report_body.mr_signer {
        bail!(
            "invalid qe mrsigner, expected {} but got {}",
            qe_identity.mrsigner.as_str(),
            hex::encode(quote.signature.qe_report_body.mr_signer)
        );
    }

    // Compare the isv_prod_id values
    if qe_identity.isvprodid != quote.signature.qe_report_body.isv_prod_id.get() {
        bail!(
            "invalid qe isv_prod_id, expected {} but got {}",
            qe_identity.isvprodid,
            quote.signature.qe_report_body.isv_prod_id.get()
        );
    }

    // Compare the attribute values
    let qe_report_attributes = quote.signature.qe_report_body.sgx_attributes;
    let qe_identity_attributes_bytes: [u8; 16] = qe_identity.attributes_bytes();
    let calculated_mask = qe_identity_attributes_bytes
        .iter()
        .zip(qe_report_attributes.iter())
        .map(|(&mask, &attribute)| mask & attribute);

    if calculated_mask
        .zip(qe_identity_attributes_bytes)
        .any(|(masked, identity)| masked != identity)
    {
        bail!("qe attrtibutes mismatch");
    }

    // Compare misc_select values
    let misc_select = quote.signature.qe_report_body.misc_select;
    let qe_identity_misc_select_bytes: [u8; 4] = qe_identity.miscselect_bytes();
    let calculated_mask = qe_identity_misc_select_bytes
        .iter()
        .zip(misc_select.as_bytes().iter())
        .map(|(&mask, &attribute)| mask & attribute);

    if calculated_mask
        .zip(qe_identity_misc_select_bytes.iter())
        .any(|(masked, &identity)| masked != identity)
    {
        bail!("qe misc_select mismatch");
    }

    let qe_tcb_status = qe_identity.get_qe_tcb_status(quote.signature.qe_report_body.isv_svn.get());

    Ok(qe_tcb_status)
}

/// Verify the quote signatures.
#[cfg(feature = "full")]
pub fn verify_quote_signatures(quote: &Quote) -> anyhow::Result<()> {
    let pck_cert_chain_data = quote.signature.get_pck_cert_chain()?;
    let pck_pk_bytes = pck_cert_chain_data.pck_cert_chain[0]
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .context("missing pck public key")?;

    let pck_pkey = VerifyingKey::from_sec1_bytes(pck_pk_bytes)
        .map_err(|e| anyhow!("failed to parse pck public key: {}", e))?;

    let qe_report_signature = Signature::from_slice(quote.signature.qe_report_signature)?;
    pck_pkey
        .verify(
            quote.signature.qe_report_body.as_bytes(),
            &qe_report_signature,
        )
        .map_err(|e| anyhow!("failed to verify qe report signature. {e}"))?;

    quote.signature.verify_qe_report()?;

    let mut key = [0u8; 65];
    key[0] = 4;
    key[1..].copy_from_slice(quote.signature.attestation_pub_key);

    if quote.header.attestation_key_type.get() != AttestationKeyType::Ecdsa256P256 as u16 {
        bail!("unsupported attestation key type");
    }

    let attest_key = VerifyingKey::from_sec1_bytes(&key)
        .map_err(|e| anyhow!("failed to parse attest key: {e}"))?;

    let header_bytes = quote.header.as_bytes();
    let body_bytes = quote.body.as_bytes();
    let mut data = Vec::with_capacity(header_bytes.len() + body_bytes.len());
    data.extend_from_slice(header_bytes);
    if quote.header.version.get() > 4 {
        // For version 5 and above, we include the quote body type and size
        data.extend_from_slice(&quote.body_type.to_le_bytes());
        data.extend_from_slice(&quote.body_size.to_le_bytes());
    }
    data.extend_from_slice(body_bytes);

    let sig = Signature::from_slice(quote.signature.isv_signature)?;
    attest_key
        .verify(&data, &sig)
        .context("failed to verify quote signature")?;

    Ok(())
}

/// Ensure the latest tcb info is not revoked, and is either up to date or only needs a configuration
/// change.
#[cfg(feature = "full")]
pub fn verify_tcb_status(
    tcb_info: &TcbInfo,
    pck_extension: &SgxPckExtension,
    quote: &Quote,
) -> anyhow::Result<(TcbStatus, TcbStatus, Vec<String>)> {
    // Make sure the tcb_info matches the enclave's model/PCE version

    let tcb_info_fmspc_bytes: [u8; 6] = tcb_info.fmspc_bytes();

    let tcb_info_pce_id_bytes: [u8; 2] = tcb_info.pce_id_bytes();

    if pck_extension.fmspc != tcb_info_fmspc_bytes {
        return Err(anyhow::anyhow!(
            "tcb fmspc mismatch (pck extension: {:?}, tcb_info: {:?})",
            pck_extension.fmspc,
            tcb_info.fmspc
        ));
    }

    if pck_extension.pceid != tcb_info_pce_id_bytes {
        return Err(anyhow::anyhow!(
            "tcb pceid mismatch (pck extension: {:?}, tcb_info: {:?})",
            pck_extension.pceid,
            tcb_info.pce_id
        ));
    }

    TcbStatus::lookup(pck_extension, tcb_info, quote)
}
