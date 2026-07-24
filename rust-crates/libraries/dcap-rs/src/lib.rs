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
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

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
use std::time::SystemTime;

#[cfg(feature = "full")]
use anyhow::{Context, anyhow, bail};
#[cfg(feature = "full")]
use chrono::{DateTime, Utc};
#[cfg(feature = "full")]
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
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

/// Runtime policy applied after cryptographic quote verification.
#[cfg(feature = "full")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DcapVerificationPolicy {
    /// Permit an SGX enclave or TDX trust domain that has its debug bit set.
    pub allow_debug: bool,
    /// Permit a TDX 1.5 quote with a non-zero migration service TD measurement.
    pub allow_service_td: bool,
    /// Require the TDX `SEPT_VE_DISABLE` attribute.
    pub require_sept_ve_disable: bool,
    /// Require every reserved TDX attribute bit to be zero.
    pub require_zero_reserved_attributes: bool,
    /// Select how TDX platform TCB revocation is enforced.
    pub tdx_tcb_revocation_policy: TdxTcbRevocationPolicy,
}

/// Selects how TDX platform TCB revocation is enforced.
#[cfg(feature = "full")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TdxTcbRevocationPolicy {
    /// Follow Intel QVL by enforcing the status of the fully matched TDX TCB Info level.
    #[default]
    IntelQvlCompatible,
    /// Also reject when the preliminary SGX/PCE match points to a revoked TDX TCB Info level.
    RejectRevokedSgxPcePartialMatch,
}

#[cfg(feature = "full")]
impl DcapVerificationPolicy {
    /// Production policy equivalent to Intel's normal quote-verification policy.
    pub const fn production() -> Self {
        Self {
            allow_debug: false,
            allow_service_td: false,
            require_sept_ve_disable: true,
            require_zero_reserved_attributes: true,
            tdx_tcb_revocation_policy: TdxTcbRevocationPolicy::IntelQvlCompatible,
        }
    }

    /// Sets how TDX platform TCB revocation is enforced.
    pub const fn with_tdx_tcb_revocation_policy(
        mut self,
        tdx_tcb_revocation_policy: TdxTcbRevocationPolicy,
    ) -> Self {
        self.tdx_tcb_revocation_policy = tdx_tcb_revocation_policy;
        self
    }
}

#[cfg(feature = "full")]
impl Default for DcapVerificationPolicy {
    fn default() -> Self {
        Self::production()
    }
}

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
    verify_dcap_quote_with_policy(
        current_time,
        collateral,
        quote,
        &DcapVerificationPolicy::production(),
    )
}

/// Verifies an SGX or TDX DCAP quote and applies the supplied runtime policy.
#[cfg(feature = "full")]
pub fn verify_dcap_quote_with_policy(
    current_time: SystemTime,
    collateral: Collateral,
    quote: Quote,
    policy: &DcapVerificationPolicy,
) -> anyhow::Result<VerifiedOutput> {
    // 1. Verify the integrity of the signature chain from the Quote to the Intel-issued PCK
    //    certificate, and that no keys in the chain have been revoked.
    use crate::types::quote::QuoteBody;
    let tcb_info = verify_integrity(current_time, &collateral, &quote)?;

    // 2. Verify the Quoting Enclave source and all signatures in the Quote.
    let qe_tcb_status = verify_quote(current_time, &collateral, &quote)?;

    reject_invalid_qe_tcb_status(qe_tcb_status)?;

    // 3. Verify the status of Intel SGX TCB described in the chain.
    let pck_extension = quote.signature.get_pck_extension()?;
    let (sgx_tcb_status, tdx_tcb_status, advisory_ids) =
        verify_tcb_status(&tcb_info, &pck_extension, &quote)?;

    enforce_platform_tcb_policy(
        quote.header.tee_type,
        sgx_tcb_status,
        tdx_tcb_status,
        policy.tdx_tcb_revocation_policy,
    )?;

    let advisory_ids = if advisory_ids.is_empty() {
        None
    } else {
        Some(advisory_ids)
    };

    // 4. If TDX type then verify the status of TDX Module status and converge and send
    let mut tcb_status;
    if quote.header.tee_type == TDX_TEE_TYPE {
        tcb_status = tdx_tcb_status;
        let td_report = quote
            .body
            .as_tdx_report_body()
            .context("TDX quote does not contain a TDX report body")?;
        let tdx_module_tcb_status = verify_tdx_module(&tcb_info, td_report)?;
        reject_invalid_tcb_status("TDX module", tdx_module_tcb_status)?;
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
            )?;
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

    validate_quote_policy(&quote.body, policy)?;

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
fn reject_invalid_tcb_status(component: &str, status: TcbStatus) -> anyhow::Result<()> {
    match status {
        TcbStatus::Revoked => bail!("{component} TCB is revoked"),
        TcbStatus::Unspecified => bail!("{component} TCB status is unspecified"),
        _ => Ok(()),
    }
}

#[cfg(feature = "full")]
fn reject_invalid_qe_tcb_status(status: QeTcbStatus) -> anyhow::Result<()> {
    match status {
        QeTcbStatus::Revoked => bail!("quoting enclave TCB is revoked"),
        QeTcbStatus::Unspecified => bail!("quoting enclave TCB status is unspecified"),
        _ => Ok(()),
    }
}

#[cfg(feature = "full")]
fn enforce_platform_tcb_policy(
    tee_type: u32,
    sgx_tcb_status: TcbStatus,
    tdx_tcb_status: TcbStatus,
    policy: TdxTcbRevocationPolicy,
) -> anyhow::Result<()> {
    if tee_type == TDX_TEE_TYPE && policy == TdxTcbRevocationPolicy::RejectRevokedSgxPcePartialMatch
    {
        reject_invalid_tcb_status("SGX/PCE partial TDX TCB Info match", sgx_tcb_status)?;
    }

    let quote_tcb_status = if tee_type == TDX_TEE_TYPE {
        tdx_tcb_status
    } else {
        sgx_tcb_status
    };

    match quote_tcb_status {
        TcbStatus::Revoked => bail!("FMSPC TCB Revoked"),
        TcbStatus::Unspecified => bail!("FMSPC TCB status is unspecified"),
        _ => Ok(()),
    }
}

#[cfg(feature = "full")]
fn validate_quote_policy(
    quote_body: &types::quote::QuoteBody,
    policy: &DcapVerificationPolicy,
) -> anyhow::Result<()> {
    use types::quote::QuoteBody;

    match quote_body {
        QuoteBody::SgxQuoteBody(report) => {
            if !policy.allow_debug && report.sgx_attributes[0] & 0x02 != 0 {
                bail!("SGX debug mode is enabled");
            }
        },
        QuoteBody::Td10QuoteBody(report) => validate_td_attributes(report.td_attributes, policy)?,
        QuoteBody::Td15QuoteBody(report) => {
            if !policy.allow_service_td && report.mr_service_td != [0; 48] {
                bail!("TDX migration service TD measurement is not zero");
            }
            validate_td_attributes(report.td_report.td_attributes, policy)?;
        },
    }

    Ok(())
}

#[cfg(feature = "full")]
fn validate_td_attributes(
    attributes: [u8; 8],
    policy: &DcapVerificationPolicy,
) -> anyhow::Result<()> {
    const DEBUG: u8 = 0x01;
    const SEPT_VE_DISABLE: u8 = 0x10;
    const RESERVED_BIT_29: u8 = 0x20;
    const PERFMON: u8 = 0x80;

    if !policy.allow_debug && attributes[0] & DEBUG != 0 {
        bail!("TDX debug mode is enabled");
    }

    if policy.require_zero_reserved_attributes
        && (attributes[0] & !DEBUG != 0
            || attributes[1] != 0
            || attributes[2] != 0
            || attributes[3] & 0x0f != 0
            || attributes[3] & RESERVED_BIT_29 != 0
            || attributes[4] != 0
            || attributes[5] != 0
            || attributes[6] != 0
            || attributes[7] & !PERFMON != 0)
    {
        bail!("reserved TDX attribute bits are set");
    }

    if policy.require_sept_ve_disable && attributes[3] & SEPT_VE_DISABLE == 0 {
        bail!("TDX SEPT_VE_DISABLE is not enabled");
    }

    Ok(())
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
    let intel_root_ca =
        X509VerifyingKey::try_from(spki).context("invalid Intel root CA public key")?;
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
    tcb_info
        .validate_id_for_tee_type(quote.header.tee_type)
        .context("TCB Info type does not match quote")?;

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
                collateral
                    .tcb_info_and_qe_identity_issuer_chain
                    .first()
                    .context("tcb issuer chain is empty")?
                    .tbs_certificate
                    .subject_public_key_info
                    .subject_public_key
                    .as_bytes()
                    .context("missing qe identity public key")?,
            )
            .context("failed to verify quote enclave identity")?,
        )
        .context("failed to verify quote enclave identity")?;
    qe_identity
        .validate_id_for_tee_type(quote.header.tee_type)
        .context("Quoting Enclave Identity type does not match quote")?;

    // Validate that current time is between issue_date and next_update
    let current_time: DateTime<Utc> = current_time.into();
    if current_time < qe_identity.issue_date || current_time > qe_identity.next_update {
        bail!("tcb info is not valid at current time");
    }

    // Compare the mr_signer values
    let qe_identity_mr_signer_bytes: [u8; 32] = qe_identity.mrsigner_bytes()?;
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
    let qe_identity_attributes_bytes: [u8; 16] = qe_identity.attributes_bytes()?;
    let qe_identity_attributes_mask: [u8; 16] = qe_identity.attributes_mask_bytes()?;
    let calculated_mask = qe_identity_attributes_mask
        .iter()
        .zip(qe_report_attributes.iter())
        .map(|(&mask, &attribute)| mask & attribute);

    if calculated_mask
        .zip(qe_identity_attributes_bytes)
        .any(|(masked, identity)| masked != identity)
    {
        bail!("qe attributes mismatch");
    }

    // Compare misc_select values
    let misc_select = quote.signature.qe_report_body.misc_select;
    let qe_identity_misc_select_bytes: [u8; 4] = qe_identity.miscselect_bytes()?;
    let qe_identity_misc_select_mask: [u8; 4] = qe_identity.miscselect_mask_bytes()?;
    let calculated_mask = qe_identity_misc_select_mask
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

/// Matches the quote and PCK extension against the supplied TCB Info.
///
/// For an SGX quote, the first returned status is the fully matched SGX status
/// and the second status is [`TcbStatus::Unspecified`]. For a TDX quote, the
/// first status belongs to the preliminary SGX/PCE match inside TDX TCB Info;
/// only the second status belongs to the fully matched SGX/PCE/TDX level.
#[cfg(feature = "full")]
pub fn verify_tcb_status(
    tcb_info: &TcbInfo,
    pck_extension: &SgxPckExtension,
    quote: &Quote,
) -> anyhow::Result<(TcbStatus, TcbStatus, Vec<String>)> {
    // Make sure the tcb_info matches the enclave's model/PCE version

    let tcb_info_fmspc_bytes: [u8; 6] = tcb_info.fmspc_bytes()?;

    let tcb_info_pce_id_bytes: [u8; 2] = tcb_info.pce_id_bytes()?;

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

#[cfg(all(test, feature = "full"))]
mod tests {
    use super::*;
    use crate::types::quote::{Quote, QuoteBody, SGX_TEE_TYPE};

    fn sample_tdx_body() -> QuoteBody {
        let quote_bytes = hex::decode(include_str!("../../../samples/quotev4.hex").trim()).unwrap();
        Quote::read(&mut quote_bytes.as_slice()).unwrap().body
    }

    fn sample_tdx_15_body() -> QuoteBody {
        let quote_bytes = include_bytes!("../../../samples/quotev5.dat");
        Quote::read(&mut quote_bytes.as_slice()).unwrap().body
    }

    #[test]
    fn revoked_and_unspecified_statuses_return_errors_without_panicking() {
        for status in [TcbStatus::Revoked, TcbStatus::Unspecified] {
            let result =
                std::panic::catch_unwind(|| reject_invalid_tcb_status("test component", status));
            assert!(result.is_ok());
            assert!(result.unwrap().is_err());
        }

        for status in [QeTcbStatus::Revoked, QeTcbStatus::Unspecified] {
            let result = std::panic::catch_unwind(|| reject_invalid_qe_tcb_status(status));
            assert!(result.is_ok());
            assert!(result.unwrap().is_err());
        }
    }

    #[test]
    fn production_policy_rejects_invalid_tdx_attributes_without_panicking() {
        let QuoteBody::Td10QuoteBody(sample_report) = sample_tdx_body() else {
            panic!("sample quote must contain a TDX 1.0 body");
        };

        for attributes in [
            [0x01, 0, 0, 0x10, 0, 0, 0, 0],
            [0x02, 0, 0, 0x10, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0, 0, 0],
        ] {
            let mut report = sample_report;
            report.td_attributes = attributes;
            let body = QuoteBody::Td10QuoteBody(report);
            let result = std::panic::catch_unwind(|| {
                validate_quote_policy(&body, &DcapVerificationPolicy::production())
            });
            assert!(result.is_ok());
            assert!(result.unwrap().is_err());
        }
    }

    #[test]
    fn policy_can_explicitly_allow_debug_tdx_quotes() {
        let mut body = sample_tdx_body();
        let QuoteBody::Td10QuoteBody(ref mut report) = body else {
            panic!("sample quote must contain a TDX 1.0 body");
        };
        report.td_attributes = [0x01, 0, 0, 0x10, 0, 0, 0, 0];

        let policy = DcapVerificationPolicy {
            allow_debug: true,
            ..DcapVerificationPolicy::production()
        };
        validate_quote_policy(&body, &policy).unwrap();
    }

    #[test]
    fn production_policy_rejects_service_td_unless_explicitly_allowed() {
        let body = sample_tdx_15_body();
        let result = std::panic::catch_unwind(|| {
            validate_quote_policy(&body, &DcapVerificationPolicy::production())
        });
        assert!(result.is_ok());
        assert!(result.unwrap().is_err());

        let policy = DcapVerificationPolicy {
            allow_service_td: true,
            ..DcapVerificationPolicy::production()
        };
        validate_quote_policy(&body, &policy).unwrap();
    }

    #[test]
    fn production_policy_is_intel_qvl_compatible() {
        assert_eq!(
            DcapVerificationPolicy::production().tdx_tcb_revocation_policy,
            TdxTcbRevocationPolicy::IntelQvlCompatible
        );
    }

    #[test]
    fn rejects_revoked_sgx_tcb_status() {
        let result = enforce_platform_tcb_policy(
            SGX_TEE_TYPE,
            TcbStatus::Revoked,
            TcbStatus::Unspecified,
            TdxTcbRevocationPolicy::IntelQvlCompatible,
        );

        assert_eq!(result.unwrap_err().to_string(), "FMSPC TCB Revoked");
    }

    #[test]
    fn intel_policy_allows_revoked_sgx_pce_partial_match_for_tdx_quote() {
        // Mirrors Intel's preliminary SGX/PCE=Revoked, complete TDX=OutOfDate case:
        // https://github.com/intel/confidential-computing.tee.dcap.qvl/blob/caedd7616d07409878d6daf5ba80f7418fec9c0d/Src/AttestationLibrary/test/UnitTests/QuoteVerifierTcbStatusUT.cpp#L103-L108
        let result = enforce_platform_tcb_policy(
            TDX_TEE_TYPE,
            TcbStatus::Revoked,
            TcbStatus::OutOfDate,
            TdxTcbRevocationPolicy::IntelQvlCompatible,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn conservative_policy_rejects_revoked_sgx_pce_partial_match_for_tdx_quote() {
        let result = enforce_platform_tcb_policy(
            TDX_TEE_TYPE,
            TcbStatus::Revoked,
            TcbStatus::OutOfDate,
            TdxTcbRevocationPolicy::RejectRevokedSgxPcePartialMatch,
        );

        assert_eq!(
            result.unwrap_err().to_string(),
            "SGX/PCE partial TDX TCB Info match TCB is revoked"
        );
    }

    #[test]
    fn rejects_revoked_tdx_tcb_status_under_both_policies() {
        for policy in [
            TdxTcbRevocationPolicy::IntelQvlCompatible,
            TdxTcbRevocationPolicy::RejectRevokedSgxPcePartialMatch,
        ] {
            let result = enforce_platform_tcb_policy(
                TDX_TEE_TYPE,
                TcbStatus::UpToDate,
                TcbStatus::Revoked,
                policy,
            );

            assert_eq!(result.unwrap_err().to_string(), "FMSPC TCB Revoked");
        }
    }
}
