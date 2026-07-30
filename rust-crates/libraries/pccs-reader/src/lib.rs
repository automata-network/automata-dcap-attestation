//! PCCS collateral reader and verification utilities.
//!
//! This crate provides functionality to fetch and verify Intel SGX/TDX attestation
//! collaterals from the Provisioning Certification Caching Service (PCCS). It can
//! read quotes and identify missing or outdated collateral materials required for
//! attestation verification.
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

/// Constants used throughout the PCCS reader, including CA names and TEE types.
pub mod constants;
mod multicall;
/// PCCS data access modules for fetching TCB info, enclave identities, and certificates.
pub mod pccs;
/// Utilities for printing collateral data to files.
pub mod printer;
mod reader;
/// PEM encoding utilities for TCB certificate chains.
pub mod tcb_pem;
/// Type definitions for collaterals, errors, and missing collateral reports.
pub mod types;

use alloy::providers::Provider;
use constants::*;
use pccs::enclave_id::{get_enclave_identity_at_address, EnclaveIdType};
use pccs::fmspc_tcb::get_tcb_info_at_address;
use pccs::pcs::get_certificate_by_id_at_address;
use printer::{print_content, print_str_content};

use chrono::{DateTime, Utc};
/// Certificate Authority identifiers for PCCS certificates.
///
/// This enum identifies the different certificate authorities in the Intel
/// SGX/TDX certificate chain hierarchy.
pub use pccs::pcs::CA;
pub use reader::{PccsReadStrategy, PccsReader};
use serde_json::Value;
use std::future::Future;
pub use types::{CollateralError, Collaterals, MissingCollateral, MissingCollateralReport};
use x509_parser::prelude::*;

const PCS_API_VERSION: u32 = 4; // Always use version 4 now
const TCB_VERSION: u32 = 3;

fn collateral_is_outdated(
    collateral: &str,
    collateral_name: &str,
) -> Result<bool, CollateralError> {
    let json_data: Value = serde_json::from_str(collateral).map_err(|error| {
        CollateralError::Validation(format!(
            "{collateral_name} collateral is not valid JSON: {error}"
        ))
    })?;

    let next_update_str = json_data
        .get(collateral_name)
        .and_then(|value| value.get("nextUpdate"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CollateralError::Validation(format!(
                "{collateral_name} collateral is missing nextUpdate"
            ))
        })?;

    let next_update_time = DateTime::parse_from_rfc3339(next_update_str).map_err(|error| {
        CollateralError::Validation(format!(
            "{collateral_name} collateral has an invalid nextUpdate value: {error}"
        ))
    })?;

    let current_time = Utc::now();
    Ok(current_time > next_update_time.with_timezone(&Utc))
}

/// Finds missing or outdated collaterals required to verify an SGX or TDX quote.
///
/// This function analyzes a raw attestation quote and checks whether all required
/// collaterals (certificates, CRLs, TCB info, enclave identities) are present and
/// up-to-date in the on-chain PCCS deployment.
///
/// # Arguments
///
/// * `provider` - An Ethereum provider to query the on-chain PCCS contract
/// * `deployment_version` - Optional version of the DCAP deployment to query
/// * `raw_quote` - Raw bytes of the attestation quote (SGX or TDX)
/// * `print` - Whether to print collateral files to disk for debugging
/// * `tcb_eval_num` - Optional TCB evaluation number to request specific TCB version
///
/// # Returns
///
/// * `Ok(Collaterals)` - All required collaterals if present and up-to-date
/// * `Err(CollateralError::Missing)` - List of missing or outdated collaterals
/// * `Err(CollateralError::Validation)` - Quote parsing or validation error
///
/// # Examples
///
/// ```no_run
/// # use pccs_reader_rs::find_missing_collaterals_from_quote;
/// # use alloy::providers::ProviderBuilder;
/// # async fn example() -> anyhow::Result<()> {
/// let provider = ProviderBuilder::new().connect_http("http://localhost:8545".parse()?);
/// let quote_bytes = hex::decode("...")?;
/// let collaterals = find_missing_collaterals_from_quote(
///     &provider,
///     None,
///     &quote_bytes,
///     false,
///     None
/// ).await?;
/// # Ok(())
/// # }
/// ```
pub async fn find_missing_collaterals_from_quote<P: Provider>(
    provider: &P,
    deployment_version: Option<automata_dcap_utils::Version>,
    raw_quote: &[u8],
    print: bool,
    tcb_eval_num: Option<u32>,
) -> Result<Collaterals, CollateralError> {
    let requirements = QuoteCollateralRequirements::parse(raw_quote)?;
    let reader = match PccsReader::from_provider(provider, deployment_version).await {
        Ok(reader) => reader,
        Err(_) => return Err(CollateralError::Missing(requirements.all_missing_report())),
    };

    find_missing_collaterals_with_requirements(&reader, requirements, print, tcb_eval_num).await
}

#[derive(Debug)]
pub(crate) struct QuoteCollateralRequirements {
    pub(crate) qe_id_type: EnclaveIdType,
    qe_id_string: &'static str,
    pub(crate) tcb_type: u8,
    pub(crate) fmspc: String,
    pub(crate) pck_type: CA,
    pck_type_string: &'static str,
}

impl QuoteCollateralRequirements {
    fn parse(raw_quote: &[u8]) -> Result<Self, CollateralError> {
        if raw_quote.len() < 8 {
            return Err(CollateralError::Validation(
                "Quote is too short: expected at least 8 bytes".to_string(),
            ));
        }

        let quote_version = u16::from_le_bytes([raw_quote[0], raw_quote[1]]);
        let tee_type = u32::from_le_bytes([raw_quote[4], raw_quote[5], raw_quote[6], raw_quote[7]]);

        if !(3..=5).contains(&quote_version) {
            return Err(CollateralError::Validation(
                "Unsupported quote version".to_string(),
            ));
        }

        if tee_type != SGX_TEE_TYPE && tee_type != TDX_TEE_TYPE {
            return Err(CollateralError::Validation(
                "Unsupported tee type".to_string(),
            ));
        }

        let mut quote_bytes_ref = raw_quote;
        let quote = dcap_rs::types::quote::Quote::read(&mut quote_bytes_ref)
            .map_err(|e| CollateralError::Validation(format!("Failed to parse quote: {}", e)))?;
        let pck_extension = quote.signature.get_pck_extension().map_err(|e| {
            CollateralError::Validation(format!("Failed to extract PCK extension: {}", e))
        })?;
        let fmspc = hex::encode(pck_extension.fmspc);
        let pck_cert_chain = quote.signature.get_pck_cert_chain().map_err(|e| {
            CollateralError::Validation(format!("Failed to extract PCK cert chain: {}", e))
        })?;
        let pck_issuer = pck_cert_chain
            .pck_cert_chain
            .first()
            .ok_or_else(|| {
                CollateralError::Validation("PCK certificate chain is empty".to_string())
            })?
            .tbs_certificate
            .issuer
            .to_string();
        let (pck_type, pck_type_string) =
            if pck_issuer.contains(constants::INTEL_PCK_PLATFORM_CA_CN) {
                (CA::PLATFORM, INTEL_PCK_PLATFORM_CA_CN)
            } else if pck_issuer.contains(constants::INTEL_PCK_PROCESSOR_CA_CN) {
                (CA::PROCESSOR, INTEL_PCK_PROCESSOR_CA_CN)
            } else {
                return Err(CollateralError::Validation(format!(
                    "Unknown PCK Issuer: {}",
                    pck_issuer
                )));
            };

        let (qe_id_type, qe_id_string, tcb_type) = if tee_type == TDX_TEE_TYPE {
            (EnclaveIdType::TDQE, "td", 1)
        } else {
            (EnclaveIdType::QE, "qe", 0)
        };

        Ok(Self {
            qe_id_type,
            qe_id_string,
            tcb_type,
            fmspc,
            pck_type,
            pck_type_string,
        })
    }

    fn all_missing_report(&self) -> MissingCollateralReport {
        MissingCollateralReport::new(vec![
            MissingCollateral::PCS(INTEL_ROOT_CA_CN.to_string(), true, true),
            MissingCollateral::QEIdentity(self.qe_id_string.to_string(), PCS_API_VERSION),
            MissingCollateral::FMSPCTCB(self.tcb_type, self.fmspc.clone(), TCB_VERSION),
            MissingCollateral::PCS(INTEL_TCB_SIGNING_CA_CN.to_string(), true, false),
            MissingCollateral::PCS(self.pck_type_string.to_string(), true, true),
        ])
    }
}

pub(crate) async fn find_missing_collaterals_with_reader<P: Provider>(
    reader: &PccsReader<'_, P>,
    raw_quote: &[u8],
    print: bool,
    tcb_eval_num: Option<u32>,
) -> Result<Collaterals, CollateralError> {
    let requirements = QuoteCollateralRequirements::parse(raw_quote)?;
    find_missing_collaterals_with_requirements(reader, requirements, print, tcb_eval_num).await
}

async fn find_missing_collaterals_with_requirements<P: Provider>(
    reader: &PccsReader<'_, P>,
    requirements: QuoteCollateralRequirements,
    print: bool,
    tcb_eval_num: Option<u32>,
) -> Result<Collaterals, CollateralError> {
    let results = match reader.read_strategy() {
        PccsReadStrategy::DirectConcurrent => {
            read_collateral_results_direct(reader, &requirements, tcb_eval_num).await
        }
        PccsReadStrategy::Multicall3 { address } => {
            multicall::read_collateral_results(reader, &requirements, tcb_eval_num, address).await
        }
    };
    let CollateralReadResults {
        root: root_result,
        signing: signing_result,
        pck: pck_result,
        qe: qe_result,
        tcb: tcb_result,
    } = results;

    let mut collaterals = Collaterals::default();
    let mut missing = Vec::new();
    process_root_result(root_result, print, &mut collaterals, &mut missing)?;
    process_qe_identity_result(
        qe_result,
        requirements.qe_id_string,
        print,
        &mut collaterals,
        &mut missing,
    )?;
    process_tcb_info_result(
        tcb_result,
        requirements.tcb_type,
        requirements.fmspc.as_str(),
        print,
        &mut collaterals,
        &mut missing,
    )?;
    process_signing_result(signing_result, print, &mut collaterals, &mut missing)?;
    process_pck_result(
        pck_result,
        requirements.pck_type_string,
        print,
        &mut collaterals,
        &mut missing,
    )?;

    if missing.is_empty() {
        Ok(collaterals)
    } else {
        Err(CollateralError::Missing(MissingCollateralReport::new(
            missing,
        )))
    }
}

pub(crate) struct CollateralReadResults {
    pub(crate) root: anyhow::Result<(Vec<u8>, Vec<u8>)>,
    pub(crate) signing: anyhow::Result<(Vec<u8>, Vec<u8>)>,
    pub(crate) pck: anyhow::Result<(Vec<u8>, Vec<u8>)>,
    pub(crate) qe: anyhow::Result<Vec<u8>>,
    pub(crate) tcb: anyhow::Result<Vec<u8>>,
}

pub(crate) async fn read_collateral_results_direct<P: Provider>(
    reader: &PccsReader<'_, P>,
    requirements: &QuoteCollateralRequirements,
    tcb_eval_num: Option<u32>,
) -> CollateralReadResults {
    let provider = reader.provider();
    let network = reader.network();
    let pcs_dao_address = network.contracts.pccs.pcs_dao;

    let root_read = get_certificate_by_id_at_address(provider, pcs_dao_address, CA::ROOT);
    let signing_read = get_certificate_by_id_at_address(provider, pcs_dao_address, CA::SIGNING);
    let pck_read =
        get_certificate_by_id_at_address(provider, pcs_dao_address, requirements.pck_type);
    let versioned_reads = async {
        match network
            .resolve_tcb_evaluation_data_number(provider, tcb_eval_num, requirements.tcb_type)
            .await
        {
            Ok(evaluation_data_number) => {
                let qe_read = async {
                    let dao_address = network
                        .contracts
                        .pccs
                        .enclave_id_dao
                        .get_address(evaluation_data_number)?;
                    get_enclave_identity_at_address(
                        provider,
                        dao_address,
                        requirements.qe_id_type,
                        PCS_API_VERSION,
                    )
                    .await
                };
                let tcb_read = async {
                    let dao_address = network
                        .contracts
                        .pccs
                        .fmspc_tcb_dao
                        .get_address(evaluation_data_number)?;
                    get_tcb_info_at_address(
                        provider,
                        dao_address,
                        requirements.tcb_type,
                        requirements.fmspc.as_str(),
                        TCB_VERSION,
                    )
                    .await
                };
                join_versioned_reads(qe_read, tcb_read).await
            }
            Err(error) => {
                let message = error.to_string();
                let qe_error: anyhow::Result<Vec<u8>> = Err(anyhow::anyhow!(
                    "Failed to resolve QE identity DAO: {message}"
                ));
                let tcb_error: anyhow::Result<Vec<u8>> = Err(anyhow::anyhow!(
                    "Failed to resolve FMSPC TCB DAO: {message}"
                ));
                (qe_error, tcb_error)
            }
        }
    };

    let (root_result, signing_result, pck_result, (qe_result, tcb_result)) =
        join_initial_reads(root_read, signing_read, pck_read, versioned_reads).await;

    CollateralReadResults {
        root: root_result,
        signing: signing_result,
        pck: pck_result,
        qe: qe_result,
        tcb: tcb_result,
    }
}

async fn join_initial_reads<Root, Signing, Pck, Versioned>(
    root: Root,
    signing: Signing,
    pck: Pck,
    versioned: Versioned,
) -> (
    Root::Output,
    Signing::Output,
    Pck::Output,
    Versioned::Output,
)
where
    Root: Future,
    Signing: Future,
    Pck: Future,
    Versioned: Future,
{
    tokio::join!(root, signing, pck, versioned)
}

async fn join_versioned_reads<Qe, Tcb>(qe: Qe, tcb: Tcb) -> (Qe::Output, Tcb::Output)
where
    Qe: Future,
    Tcb: Future,
{
    tokio::join!(qe, tcb)
}

fn process_root_result(
    result: anyhow::Result<(Vec<u8>, Vec<u8>)>,
    print: bool,
    collaterals: &mut Collaterals,
    missing: &mut Vec<MissingCollateral>,
) -> Result<(), CollateralError> {
    match result {
        Ok((root, crl)) => {
            if root.is_empty() {
                missing.push(MissingCollateral::PCS(
                    INTEL_ROOT_CA_CN.to_string(),
                    true,
                    false,
                ));
            } else if crl.is_empty() {
                missing.push(MissingCollateral::PCS(
                    INTEL_ROOT_CA_CN.to_string(),
                    false,
                    true,
                ));
            } else {
                if print {
                    print_content("rootca.der", &root).map_err(|error| {
                        CollateralError::Validation(format!("failed to write rootca.der: {error}"))
                    })?;
                    print_content("rootcrl.der", &crl).map_err(|error| {
                        CollateralError::Validation(format!("failed to write rootcrl.der: {error}"))
                    })?;
                }
                let root_cert = parse_x509_der(&root)?;
                if !root_cert.validity.is_valid() {
                    missing.push(MissingCollateral::PCS(
                        INTEL_ROOT_CA_CN.to_string(),
                        true,
                        false,
                    ));
                } else {
                    let root_ca_crl = parse_crl_der(&crl)?;
                    if let Some(next_update) = root_ca_crl.next_update() {
                        let now = x509_parser::time::ASN1Time::now();
                        if next_update < now {
                            missing.push(MissingCollateral::PCS(
                                INTEL_ROOT_CA_CN.to_string(),
                                false,
                                true,
                            ));
                        }
                    }
                }
                collaterals.root_ca = root;
                collaterals.root_ca_crl = crl;
            }
        }
        Err(_) => missing.push(MissingCollateral::PCS(
            INTEL_ROOT_CA_CN.to_string(),
            true,
            true,
        )),
    }
    Ok(())
}

fn process_qe_identity_result(
    result: anyhow::Result<Vec<u8>>,
    qe_id_string: &str,
    print: bool,
    collaterals: &mut Collaterals,
    missing: &mut Vec<MissingCollateral>,
) -> Result<(), CollateralError> {
    match result {
        Ok(qe_id_content) => {
            let qe_id_str = std::str::from_utf8(&qe_id_content).map_err(|error| {
                CollateralError::Validation(format!(
                    "QE identity collateral is not valid UTF-8: {error}"
                ))
            })?;
            if collateral_is_outdated(qe_id_str, "enclaveIdentity")? {
                missing.push(MissingCollateral::QEIdentity(
                    qe_id_string.to_string(),
                    PCS_API_VERSION,
                ));
            } else {
                if print {
                    let filename = format!("identity-{}-v{}.json", qe_id_string, PCS_API_VERSION);
                    print_str_content(&filename, qe_id_str).map_err(|error| {
                        CollateralError::Validation(format!("failed to write {filename}: {error}"))
                    })?;
                }
                collaterals.qe_identity = qe_id_str.to_string();
            }
        }
        Err(_) => missing.push(MissingCollateral::QEIdentity(
            qe_id_string.to_string(),
            PCS_API_VERSION,
        )),
    }
    Ok(())
}

fn process_tcb_info_result(
    result: anyhow::Result<Vec<u8>>,
    tcb_type: u8,
    fmspc: &str,
    print: bool,
    collaterals: &mut Collaterals,
    missing: &mut Vec<MissingCollateral>,
) -> Result<(), CollateralError> {
    match result {
        Ok(tcb_content) => {
            let tcb_str = std::str::from_utf8(&tcb_content).map_err(|error| {
                CollateralError::Validation(format!(
                    "TCB info collateral is not valid UTF-8: {error}"
                ))
            })?;
            if collateral_is_outdated(tcb_str, "tcbInfo")? {
                missing.push(MissingCollateral::FMSPCTCB(
                    tcb_type,
                    fmspc.to_string(),
                    TCB_VERSION,
                ));
            } else {
                let tcb_type_string = match tcb_type {
                    0 => "sgx",
                    1 => "tdx",
                    _ => {
                        return Err(CollateralError::Validation(format!(
                            "unsupported TCB type {tcb_type}"
                        )));
                    }
                };
                if print {
                    let filename = format!("tcbinfo-{}-v{}.json", tcb_type_string, TCB_VERSION);
                    print_str_content(&filename, tcb_str).map_err(|error| {
                        CollateralError::Validation(format!("failed to write {filename}: {error}"))
                    })?;
                }
                collaterals.tcb_info = tcb_str.to_string();
            }
        }
        Err(_) => missing.push(MissingCollateral::FMSPCTCB(
            tcb_type,
            fmspc.to_string(),
            TCB_VERSION,
        )),
    }
    Ok(())
}

fn process_signing_result(
    result: anyhow::Result<(Vec<u8>, Vec<u8>)>,
    print: bool,
    collaterals: &mut Collaterals,
    missing: &mut Vec<MissingCollateral>,
) -> Result<(), CollateralError> {
    match result {
        Ok((signing_ca, _)) => {
            if signing_ca.is_empty() {
                missing.push(MissingCollateral::PCS(
                    INTEL_TCB_SIGNING_CA_CN.to_string(),
                    true,
                    false,
                ));
            } else {
                let signing_ca_cert = parse_x509_der(&signing_ca)?;
                if !signing_ca_cert.validity.is_valid() {
                    missing.push(MissingCollateral::PCS(
                        INTEL_TCB_SIGNING_CA_CN.to_string(),
                        true,
                        false,
                    ));
                } else {
                    if print {
                        print_content("signingca.der", &signing_ca).map_err(|error| {
                            CollateralError::Validation(format!(
                                "failed to write signingca.der: {error}"
                            ))
                        })?;
                    }
                    collaterals.tcb_signing_ca = signing_ca;
                }
            }
        }
        Err(_) => missing.push(MissingCollateral::PCS(
            INTEL_TCB_SIGNING_CA_CN.to_string(),
            true,
            false,
        )),
    }
    Ok(())
}

fn process_pck_result(
    result: anyhow::Result<(Vec<u8>, Vec<u8>)>,
    pck_type_string: &str,
    print: bool,
    collaterals: &mut Collaterals,
    missing: &mut Vec<MissingCollateral>,
) -> Result<(), CollateralError> {
    match result {
        Ok((pck_ca_cert, pck_ca_crl)) => {
            if pck_ca_cert.is_empty() {
                missing.push(MissingCollateral::PCS(
                    pck_type_string.to_string(),
                    true,
                    false,
                ));
            } else if pck_ca_crl.is_empty() {
                missing.push(MissingCollateral::PCS(
                    pck_type_string.to_string(),
                    false,
                    true,
                ));
            } else {
                if print {
                    let filename = format!("{}.der", pck_type_string);
                    let crl_filename = format!("{}-crl.der", pck_type_string);
                    print_content(&filename, &pck_ca_cert).map_err(|error| {
                        CollateralError::Validation(format!("failed to write {filename}: {error}"))
                    })?;
                    print_content(&crl_filename, &pck_ca_crl).map_err(|error| {
                        CollateralError::Validation(format!(
                            "failed to write {crl_filename}: {error}"
                        ))
                    })?;
                }
                let pck_cert_parsed = parse_x509_der(&pck_ca_cert)?;
                if !pck_cert_parsed.validity.is_valid() {
                    missing.push(MissingCollateral::PCS(
                        pck_type_string.to_string(),
                        true,
                        false,
                    ));
                } else {
                    let pck_ca_crl_parsed = parse_crl_der(&pck_ca_crl)?;
                    if let Some(next_update) = pck_ca_crl_parsed.next_update() {
                        let now = x509_parser::time::ASN1Time::now();
                        if next_update < now {
                            missing.push(MissingCollateral::PCS(
                                pck_type_string.to_string(),
                                false,
                                true,
                            ));
                        }
                    }
                    collaterals.pck_crl = pck_ca_crl;
                }
            }
        }
        Err(_) => missing.push(MissingCollateral::PCS(
            pck_type_string.to_string(),
            true,
            true,
        )),
    }
    Ok(())
}

/// Parses an X.509 certificate from DER-encoded bytes.
///
/// # Arguments
///
/// * `raw_bytes` - DER-encoded certificate bytes
///
/// # Returns
///
/// Parsed X.509 certificate with lifetime tied to input bytes
///
pub fn parse_x509_der<'a>(raw_bytes: &'a [u8]) -> Result<X509Certificate<'a>, CollateralError> {
    let (_, cert) = X509Certificate::from_der(raw_bytes).map_err(|error| {
        CollateralError::Validation(format!("invalid X.509 certificate DER: {error}"))
    })?;
    Ok(cert)
}

/// Parses a Certificate Revocation List (CRL) from DER-encoded bytes.
///
/// # Arguments
///
/// * `raw_bytes` - DER-encoded CRL bytes
///
/// # Returns
///
/// Parsed CRL with lifetime tied to input bytes
///
pub fn parse_crl_der<'a>(
    raw_bytes: &'a [u8],
) -> Result<CertificateRevocationList<'a>, CollateralError> {
    let (_, crl) = CertificateRevocationList::from_der(raw_bytes).map_err(|error| {
        CollateralError::Validation(format!("invalid certificate revocation list DER: {error}"))
    })?;
    Ok(crl)
}

#[cfg(test)]
mod test {
    use super::*;
    use alloy::primitives::{Bytes, U64};
    use alloy::providers::ProviderBuilder;
    use alloy::sol_types::SolCall;
    use alloy::transports::mock::Asserter;
    use automata_dcap_evm_bindings::r#i_enclave_identity_dao::IEnclaveIdentityDao::{
        getEnclaveIdentityCall, EnclaveIdentityJsonObj,
    };
    use automata_dcap_evm_bindings::r#i_fmspc_tcb_dao::IFmspcTcbDao::{
        getTcbInfoCall, TcbInfoJsonObj,
    };
    use automata_dcap_evm_bindings::r#i_pcs_dao::IPcsDao::{
        getCertificateByIdCall, getCertificateByIdReturn,
    };
    use automata_dcap_evm_bindings::r#i_tcb_eval_dao::ITcbEvalDao::standardCall;
    use automata_dcap_network_registry::Network;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::sync::Barrier;

    fn get_default_provider() -> impl Provider {
        let provider =
            Network::create_provider(&Network::default_network(None).unwrap(), None, None)
                .expect("Failed to get provider from default network");
        provider
    }

    fn load_quote(name: &str) -> Vec<u8> {
        let cargo_manifest_dir = env!("CARGO_MANIFEST_DIR");
        let quote_path = format!("{}/../../samples/{name}", cargo_manifest_dir);
        let quote_hex = std::fs::read_to_string(quote_path).unwrap();
        hex::decode(quote_hex.trim()).unwrap()
    }

    fn push_empty_collateral_responses(asserter: &Asserter, include_standard: bool) {
        let empty_certificate = getCertificateByIdReturn {
            cert: Bytes::new(),
            crl: Bytes::new(),
        };
        for _ in 0..3 {
            asserter.push_success(&Bytes::from(getCertificateByIdCall::abi_encode_returns(
                &empty_certificate,
            )));
        }
        if include_standard {
            asserter.push_success(&Bytes::from(standardCall::abi_encode_returns(&19)));
        }
        asserter.push_success(&Bytes::from(getEnclaveIdentityCall::abi_encode_returns(
            &EnclaveIdentityJsonObj {
                identityStr: String::new(),
                signature: Bytes::new(),
            },
        )));
        asserter.push_success(&Bytes::from(getTcbInfoCall::abi_encode_returns(
            &TcbInfoJsonObj {
                tcbInfoStr: String::new(),
                signature: Bytes::new(),
            },
        )));
        asserter.push_success(&Bytes::new());
    }

    #[test]
    fn short_quote_returns_validation_error() {
        let error = QuoteCollateralRequirements::parse(&[0; 7]).unwrap_err();
        assert!(matches!(error, CollateralError::Validation(_)));
        assert_eq!(
            error.to_string(),
            "Quote is too short: expected at least 8 bytes"
        );
    }

    #[test]
    fn malformed_json_collateral_returns_validation_error_without_panicking() {
        for collateral in [
            "not-json",
            r#"{"enclaveIdentity":{}}"#,
            r#"{"enclaveIdentity":{"nextUpdate":"not-a-date"}}"#,
        ] {
            let result =
                std::panic::catch_unwind(|| collateral_is_outdated(collateral, "enclaveIdentity"));
            assert!(result.is_ok());
            assert!(matches!(
                result.unwrap(),
                Err(CollateralError::Validation(_))
            ));
        }
    }

    #[test]
    fn malformed_der_returns_validation_error_without_panicking() {
        let certificate_result = std::panic::catch_unwind(|| parse_x509_der(&[0xff]));
        assert!(certificate_result.is_ok());
        assert!(matches!(
            certificate_result.unwrap(),
            Err(CollateralError::Validation(_))
        ));

        let crl_result = std::panic::catch_unwind(|| parse_crl_der(&[0xff]));
        assert!(crl_result.is_ok());
        assert!(matches!(
            crl_result.unwrap(),
            Err(CollateralError::Validation(_))
        ));
    }

    #[test]
    fn invalid_utf8_collateral_returns_validation_error_without_panicking() {
        let result = std::panic::catch_unwind(|| {
            let mut collaterals = Collaterals::default();
            let mut missing = Vec::new();
            process_qe_identity_result(Ok(vec![0xff]), "td", false, &mut collaterals, &mut missing)
        });
        assert!(result.is_ok());
        assert!(matches!(
            result.unwrap(),
            Err(CollateralError::Validation(_))
        ));
    }

    #[test]
    fn quote_requirements_select_sgx_and_tdx_collateral() {
        let sgx = QuoteCollateralRequirements::parse(&load_quote("quotev3.hex")).unwrap();
        assert_eq!(sgx.qe_id_type, EnclaveIdType::QE);
        assert_eq!(sgx.qe_id_string, "qe");
        assert_eq!(sgx.tcb_type, 0);

        let tdx = QuoteCollateralRequirements::parse(&load_quote("quotev4.hex")).unwrap();
        assert_eq!(tdx.qe_id_type, EnclaveIdType::TDQE);
        assert_eq!(tdx.qe_id_string, "td");
        assert_eq!(tdx.tcb_type, 1);
    }

    #[test]
    fn shared_lookup_failure_preserves_missing_collateral_order() {
        let requirements = QuoteCollateralRequirements::parse(&load_quote("quotev4.hex")).unwrap();
        let messages = requirements
            .all_missing_report()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();

        assert_eq!(messages.len(), 5);
        assert!(messages[0].contains(INTEL_ROOT_CA_CN));
        assert!(messages[1].contains("Missing Enclave Identity: td"));
        assert!(messages[2].contains("Missing TCB: 1"));
        assert!(messages[3].contains(INTEL_TCB_SIGNING_CA_CN));
        assert!(messages[4].contains(requirements.pck_type_string));
    }

    #[tokio::test]
    async fn initial_reads_start_concurrently() {
        let barrier = Arc::new(Barrier::new(5));
        let started = Arc::new(AtomicUsize::new(0));
        let read = |value| {
            let barrier = barrier.clone();
            let started = started.clone();
            async move {
                started.fetch_add(1, Ordering::SeqCst);
                barrier.wait().await;
                value
            }
        };

        let task = tokio::spawn(join_initial_reads(read(1), read(2), read(3), read(4)));
        barrier.wait().await;
        assert_eq!(started.load(Ordering::SeqCst), 4);
        assert_eq!(task.await.unwrap(), (1, 2, 3, 4));
    }

    #[tokio::test]
    async fn versioned_reads_start_concurrently() {
        let barrier = Arc::new(Barrier::new(3));
        let started = Arc::new(AtomicUsize::new(0));
        let read = |value| {
            let barrier = barrier.clone();
            let started = started.clone();
            async move {
                started.fetch_add(1, Ordering::SeqCst);
                barrier.wait().await;
                value
            }
        };

        let task = tokio::spawn(join_versioned_reads(read(1), read(2)));
        barrier.wait().await;
        assert_eq!(started.load(Ordering::SeqCst), 2);
        assert_eq!(task.await.unwrap(), (1, 2));
    }

    #[tokio::test]
    async fn compatibility_function_uses_seven_rpc_requests() {
        let network = Network::default_network(None).unwrap();
        let asserter = Asserter::new();
        asserter.push_success(&U64::from(network.chain_id));
        push_empty_collateral_responses(&asserter, true);

        let provider = ProviderBuilder::new().connect_mocked_client(asserter.clone());
        let error = find_missing_collaterals_from_quote(
            &provider,
            None,
            &load_quote("quotev4.hex"),
            false,
            None,
        )
        .await
        .unwrap_err();

        assert!(matches!(error, CollateralError::Missing(_)));
        assert_eq!(asserter.read_q().len(), 1);
    }

    #[tokio::test]
    async fn reader_with_network_uses_six_rpc_requests() {
        let network = Network::default_network(None).unwrap();
        let asserter = Asserter::new();
        push_empty_collateral_responses(&asserter, true);
        let provider = ProviderBuilder::new().connect_mocked_client(asserter.clone());
        let reader = PccsReader::from_network(&provider, network);

        let error = reader
            .find_missing_collaterals_from_quote(&load_quote("quotev4.hex"), false, None)
            .await
            .unwrap_err();

        assert!(matches!(error, CollateralError::Missing(_)));
        assert_eq!(asserter.read_q().len(), 1);
    }

    #[tokio::test]
    async fn requested_evaluation_number_uses_five_rpc_requests() {
        let network = Network::default_network(None).unwrap();
        let asserter = Asserter::new();
        push_empty_collateral_responses(&asserter, false);
        let provider = ProviderBuilder::new().connect_mocked_client(asserter.clone());
        let reader = PccsReader::from_network(&provider, network);

        let error = reader
            .find_missing_collaterals_from_quote(&load_quote("quotev4.hex"), false, Some(19))
            .await
            .unwrap_err();

        assert!(matches!(error, CollateralError::Missing(_)));
        assert_eq!(asserter.read_q().len(), 1);
    }

    #[tokio::test]
    async fn test_v3() {
        let quote = load_quote("quotev3.hex");

        let res =
            find_missing_collaterals_from_quote(&get_default_provider(), None, &quote, false, None)
                .await
                .unwrap();

        println!("{:?}", res);

        let test_pem_chain = tcb_pem::generate_tcb_issuer_chain_pem(
            res.tcb_signing_ca.as_slice(),
            res.root_ca.as_slice(),
        )
        .unwrap();

        println!("Test PEM Chain:\n{}", test_pem_chain);
    }

    #[tokio::test]
    async fn test_v4() {
        let quote = load_quote("quotev4.hex");
        let res =
            find_missing_collaterals_from_quote(&get_default_provider(), None, &quote, false, None)
                .await
                .unwrap();

        println!("{:?}", res);
    }

    #[tokio::test]
    async fn multicall3_is_deployed_on_the_default_network() {
        use alloy::providers::MULTICALL3_ADDRESS;

        let provider = get_default_provider();
        let code = provider
            .get_code_at(MULTICALL3_ADDRESS)
            .await
            .expect("failed to read the Multicall3 deployment");
        assert!(!code.is_empty(), "Multicall3 is not deployed");
    }

    #[tokio::test]
    async fn test_v4_multicall3() {
        let provider = get_default_provider();
        let reader = PccsReader::from_provider(&provider, None)
            .await
            .unwrap()
            .with_read_strategy(PccsReadStrategy::multicall3());
        let result = reader
            .find_missing_collaterals_from_quote(&load_quote("quotev4.hex"), false, None)
            .await
            .unwrap();

        assert!(!result.tcb_info.is_empty());
        assert!(!result.qe_identity.is_empty());
        assert!(!result.root_ca.is_empty());
        assert!(!result.tcb_signing_ca.is_empty());
        assert!(!result.root_ca_crl.is_empty());
        assert!(!result.pck_crl.is_empty());
    }

    #[tokio::test]
    async fn test_v4_multicall3_with_known_network_and_evaluation_number() {
        let provider = get_default_provider();
        let network = Network::default_network(None).unwrap();
        let reader = PccsReader::from_network(&provider, network)
            .with_read_strategy(PccsReadStrategy::multicall3());
        let result = reader
            .find_missing_collaterals_from_quote(&load_quote("quotev4.hex"), false, Some(19))
            .await
            .unwrap();

        assert!(!result.tcb_info.is_empty());
        assert!(!result.qe_identity.is_empty());
        assert!(!result.root_ca.is_empty());
        assert!(!result.tcb_signing_ca.is_empty());
        assert!(!result.root_ca_crl.is_empty());
        assert!(!result.pck_crl.is_empty());
    }
}
