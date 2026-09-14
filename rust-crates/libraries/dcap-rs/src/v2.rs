//! Identity-bearing verification. Legacy entry points and serializers are unchanged.
use crate::types::{
    VerifiedOutputV2, collateral::Collateral, quote::Quote, sgx_x509::SgxPckExtension,
    tcb_info::TcbInfoVersion,
};
use crate::{DcapVerificationPolicy, verify_dcap_quote_with_policy_ref};
use alloy_sol_types::{SolType, sol};
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Verify using the production policy at the same timestamp committed to OutputV2.
pub fn verify_dcap_quote_v2(
    current_time: SystemTime,
    collateral: &Collateral,
    raw_quote: &[u8],
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
        &DcapVerificationPolicy::production(),
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
        full_quote_hash: Sha256::digest(raw_quote).into(),
        quote_body: verified.quote_body.as_bytes().to_vec(),
        advisory_ids: verified.advisory_ids.unwrap_or_default(),
    })
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

/// Guest entry points commit these exact bytes, with no length prefix or hash trailer.
pub fn verify_guest_input_v2(input: &[u8]) -> Result<Vec<u8>> {
    let (collateral, quote, timestamp) = GuestInputV2::abi_decode_params(input)?;
    let collateral = Collateral::sol_abi_decode(&collateral)?;
    let time = UNIX_EPOCH
        .checked_add(Duration::from_secs(timestamp))
        .context("verification timestamp overflow")?;
    verify_dcap_quote_v2(time, &collateral, &quote)?.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ca_presence_matrix() {
        assert!(validate_piid_ca("Intel SGX PCK Platform CA", true).is_ok());
        assert!(validate_piid_ca("Intel SGX PCK Platform CA", false).is_err());
        assert!(validate_piid_ca("Intel SGX PCK Processor CA", false).is_ok());
        assert!(validate_piid_ca("Intel SGX PCK Processor CA", true).is_err());
        assert!(validate_piid_ca("untrusted", true).is_err());
    }
}
