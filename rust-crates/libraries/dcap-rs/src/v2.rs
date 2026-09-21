//! Identity-bearing verification. Legacy entry points and serializers are unchanged.
use crate::types::{
    VerifiedOutputV2, collateral::Collateral, quote::Quote, sgx_x509::SgxPckExtension,
    tcb_info::TcbInfoVersion,
};
use crate::utils::keccak;
use crate::{DcapVerificationPolicy, verify_dcap_quote_with_policy_ref};
use alloy_sol_types::{SolType, sol};
use anyhow::{Context, Result, ensure};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Verify using the production policy at the same timestamp committed to OutputV2.
pub fn verify_dcap_quote_v2(
    current_time: SystemTime,
    collateral: &Collateral,
    raw_quote: &[u8],
) -> Result<VerifiedOutputV2> {
    verify_dcap_quote_v2_with_min_check(current_time, collateral, raw_quote, false)
}

/// Minimal mode skips workload attributes only. Authentication, framing, TCB
/// status, collateral validity, and PPID/PIID semantics are always enforced.
pub fn verify_dcap_quote_v2_with_min_check(
    current_time: SystemTime,
    collateral: &Collateral,
    raw_quote: &[u8],
    min_check: bool,
) -> Result<VerifiedOutputV2> {
    let mut remaining = raw_quote;
    let quote = Quote::read(&mut remaining)?;
    ensure!(remaining.is_empty(), "trailing bytes after quote");
    let chain = quote.signature.get_pck_cert_chain()?;
    let tcb_info = collateral.tcb_info.get_tcb_info()?;
    ensure!(
        tcb_info.version == TcbInfoVersion::V3,
        "V2 requires PCS API v4 / TCB Info v3"
    );
    let qe = collateral.qe_identity.get_enclave_identity()?;
    ensure!(
        qe.version == 2,
        "V2 requires QE Identity v2 from PCS API v4"
    );

    let verified = verify_dcap_quote_with_policy_ref(
        current_time,
        collateral,
        quote,
        &verification_policy(min_check),
    )?;
    // Do not apply issuer/identity policy until the certificate chain and quote have been authenticated.
    let leaf = chain.pck_cert_chain.first().context("missing PCK leaf")?;
    let extensions = leaf
        .tbs_certificate
        .extensions
        .as_ref()
        .context("missing PCK extensions")?;
    ensure!(
        extensions
            .iter()
            .filter(|ext| SgxPckExtension::is_pck_ext(ext.extn_id.to_string()))
            .count()
            == 1,
        "duplicate or missing SGX extension"
    );
    let names: Vec<_> = leaf
        .tbs_certificate
        .issuer
        .0
        .iter()
        .flat_map(|rdn| rdn.0.iter())
        .filter(|attr| attr.oid.to_string() == "2.5.4.3")
        .collect();
    ensure!(names.len() == 1, "ambiguous PCK issuer common name");
    let issuer = std::str::from_utf8(names[0].value.value())?;
    let piid = chain.pck_extension.platform_instance_id();
    validate_piid_ca(issuer, piid.is_some())?;
    let signing_chain = &collateral.tcb_info_and_qe_identity_issuer_chain;
    ensure!(
        signing_chain.len() == 2,
        "expected signing and root certificates"
    );
    Ok(VerifiedOutputV2 {
        format_major_version: 2,
        format_minor_version: 1,
        quote_version: verified.quote_version,
        quote_body_type: verified.quote_body_type,
        tcb_status: verified.tcb_status,
        fmspc: verified.fmspc,
        ppid: chain.pck_extension.ppid,
        piid: piid.unwrap_or([0; 16]),
        piid_present: piid.is_some(),
        timestamp: current_time.duration_since(UNIX_EPOCH)?.as_secs(),
        collateral_hashes: [
            tcb_info.get_content_hash()?,
            qe.get_content_hash()?,
            Collateral::get_cert_hash(&signing_chain[1])?,
            Collateral::get_cert_hash(&signing_chain[0])?,
            Collateral::get_crl_hash(&collateral.root_ca_crl)?,
            Collateral::get_crl_hash(&collateral.pck_crl)?,
        ],
        full_quote_hash: keccak::hash(raw_quote),
        quote_body_hash: keccak::hash(verified.quote_body.as_bytes()),
        advisory_ids: verified.advisory_ids.unwrap_or_default(),
    })
}

fn verification_policy(min_check: bool) -> DcapVerificationPolicy {
    DcapVerificationPolicy {
        allow_debug: min_check,
        allow_service_td: min_check,
        require_sept_ve_disable: !min_check,
        require_zero_reserved_attributes: !min_check,
        ..DcapVerificationPolicy::production()
    }
}

fn validate_piid_ca(issuer: &str, present: bool) -> Result<()> {
    match issuer {
        "Intel SGX PCK Platform CA" => ensure!(present, "Platform CA requires PIID"),
        "Intel SGX PCK Processor CA" => ensure!(!present, "Processor CA forbids PIID"),
        _ => anyhow::bail!("unsupported PCK issuer"),
    }
    Ok(())
}

/// Common guest input ABI for all V2 backends; no identities are supplied by the host.
type GuestInputV2 = sol!((bytes, bytes, uint64));

pub fn encode_guest_input_v2(
    collateral: &Collateral,
    quote: &[u8],
    timestamp: u64,
) -> Result<Vec<u8>> {
    Ok(GuestInputV2::abi_encode_params(&(
        collateral.sol_abi_encode()?,
        quote,
        timestamp,
    )))
}

/// Strict guest entrypoint. Mode is selected by the program, never an input flag.
pub fn verify_guest_input_v2(input: &[u8]) -> Result<Vec<u8>> {
    verify_guest_input_v2_mode(input, false)
}

/// Minimal guest entrypoint, assigned a different native program ID.
pub fn verify_guest_input_v2_minimal(input: &[u8]) -> Result<Vec<u8>> {
    verify_guest_input_v2_mode(input, true)
}

fn verify_guest_input_v2_mode(input: &[u8], min_check: bool) -> Result<Vec<u8>> {
    let (collateral, quote, timestamp) = GuestInputV2::abi_decode_params(input)?;
    let collateral = Collateral::sol_abi_decode(&collateral)?;
    let time = UNIX_EPOCH
        .checked_add(Duration::from_secs(timestamp))
        .context("verification timestamp overflow")?;
    verify_dcap_quote_v2_with_min_check(time, &collateral, &quote, min_check)?.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::quote::QuoteBody;

    #[test]
    fn minimal_policy_changes_only_workload_attributes() {
        let strict = verification_policy(false);
        let minimal = verification_policy(true);
        assert_eq!(strict, DcapVerificationPolicy::production());
        assert_eq!(
            minimal.tdx_tcb_revocation_policy,
            strict.tdx_tcb_revocation_policy
        );
        assert!(minimal.allow_debug && minimal.allow_service_td);
        assert!(!minimal.require_sept_ve_disable && !minimal.require_zero_reserved_attributes);

        let raw = hex::decode(include_str!("../../../samples/quotev4.hex").trim()).unwrap();
        let QuoteBody::Td10QuoteBody(report) = Quote::read(&mut raw.as_slice()).unwrap().body
        else {
            panic!("expected TDX 1.0");
        };
        for bit in 0..64 {
            let mut changed = report;
            changed.td_attributes = ((1u64 << 28) | (1u64 << bit)).to_le_bytes();
            let body = QuoteBody::Td10QuoteBody(changed);
            assert!(crate::validate_quote_policy(&body, &minimal).is_ok());
            assert_eq!(
                crate::validate_quote_policy(&body, &strict).is_ok(),
                matches!(bit, 28 | 30 | 31 | 63)
            );
        }
        let mut changed = report;
        changed.td_attributes = [0; 8];
        let body = QuoteBody::Td10QuoteBody(changed);
        assert!(crate::validate_quote_policy(&body, &strict).is_err());
        assert!(crate::validate_quote_policy(&body, &minimal).is_ok());
        let body = Quote::read(&mut include_bytes!("../../../samples/quotev5.dat").as_slice())
            .unwrap()
            .body;
        assert!(crate::validate_quote_policy(&body, &strict).is_err());
        assert!(crate::validate_quote_policy(&body, &minimal).is_ok());
    }
    #[test]
    fn ca_presence_matrix() {
        assert!(validate_piid_ca("Intel SGX PCK Platform CA", true).is_ok());
        assert!(validate_piid_ca("Intel SGX PCK Platform CA", false).is_err());
        assert!(validate_piid_ca("Intel SGX PCK Processor CA", false).is_ok());
        assert!(validate_piid_ca("Intel SGX PCK Processor CA", true).is_err());
        assert!(validate_piid_ca("untrusted", true).is_err());
    }
}
