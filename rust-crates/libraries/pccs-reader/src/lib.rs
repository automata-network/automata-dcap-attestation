//! PCCS collateral reader and verification utilities.
//!
//! This crate provides functionality to fetch and verify Intel SGX/TDX attestation
//! collaterals from the Provisioning Certification Caching Service (PCCS). It can
//! read quotes and identify missing or outdated collateral materials required for
//! attestation verification.

/// Constants used throughout the PCCS reader, including CA names and TEE types.
pub mod constants;
/// PCCS data access modules for fetching TCB info, enclave identities, and certificates.
pub mod pccs;
/// Utilities for printing collateral data to files.
pub mod printer;
/// PEM encoding utilities for TCB certificate chains.
pub mod tcb_pem;
/// Type definitions for collaterals, errors, and missing collateral reports.
pub mod types;

use alloy::providers::Provider;
use constants::*;
use pccs::enclave_id::{get_enclave_identity, EnclaveIdType};
use pccs::fmspc_tcb::get_tcb_info;
use pccs::pcs::get_certificate_by_id;
use printer::{print_content, print_str_content};

use chrono::{DateTime, Utc};
/// Certificate Authority identifiers for PCCS certificates.
///
/// This enum identifies the different certificate authorities in the Intel
/// SGX/TDX certificate chain hierarchy.
pub use pccs::pcs::CA;
use serde_json::Value;
pub use types::{CollateralError, Collaterals, MissingCollateral, MissingCollateralReport};
use x509_parser::prelude::*;

const PCS_API_VERSION: u32 = 4; // Always use version 4 now
const TCB_VERSION: u32 = 3;

fn collateral_is_outdated(eid: &str, collateral_name: &str) -> bool {
    let json_data: Value =
        serde_json::from_str(&eid).expect("unable to convert collateral to json");

    let next_update_str = json_data[&collateral_name]["nextUpdate"]
        .as_str()
        .expect("field 'nextUpdate' is not found!");

    let next_update_time =
        DateTime::parse_from_rfc3339(next_update_str).expect("Parsing 'nextUpdate' failed!");

    let current_time = Utc::now();
    let outdated = current_time > next_update_time.with_timezone(&Utc);
    if outdated {
        println!(
            "Collateral {} is outdated! nextUpdate: {}",
            collateral_name, next_update_str
        );
    }

    outdated
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
/// # use automata_dcap_pccs_reader::find_missing_collaterals_from_quote;
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
    let mut ret: Collaterals = Collaterals::default();
    let mut missing: Vec<MissingCollateral> = Vec::new();

    // Step 0: read the version and tee type
    let quote_version = u16::from_le_bytes([raw_quote[0], raw_quote[1]]);
    let tee_type = u32::from_le_bytes([raw_quote[4], raw_quote[5], raw_quote[6], raw_quote[7]]);

    if quote_version < 3 || quote_version > 5 {
        return Err(CollateralError::Validation(
            "Unsupported quote version".to_string(),
        ));
    }

    if tee_type != SGX_TEE_TYPE && tee_type != TDX_TEE_TYPE {
        return Err(CollateralError::Validation(
            "Unsupported tee type".to_string(),
        ));
    }

    // Step 1: Check ROOT CRLs
    match get_certificate_by_id(provider, deployment_version, CA::ROOT).await {
        Ok((root, crl)) => {
            if root.len() == 0 {
                missing.push(MissingCollateral::PCS(
                    INTEL_ROOT_CA_CN.to_string(),
                    true,
                    false,
                ));
            } else if crl.len() == 0 {
                missing.push(MissingCollateral::PCS(
                    INTEL_ROOT_CA_CN.to_string(),
                    false,
                    true,
                ));
            } else {
                if print {
                    print_content("rootca.der", &root).unwrap();
                    print_content("rootcrl.der", &crl).unwrap();
                }
                let root_cert = parse_x509_der(&root);
                if !root_cert.validity.is_valid() {
                    missing.push(MissingCollateral::PCS(
                        INTEL_ROOT_CA_CN.to_string(),
                        true,
                        false,
                    ));
                } else {
                    let root_ca_crl = parse_crl_der(&crl);
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
                ret.root_ca = root;
                ret.root_ca_crl = crl;
            }
        }
        _ => {
            missing.push(MissingCollateral::PCS(
                INTEL_ROOT_CA_CN.to_string(),
                true,
                true,
            ));
        }
    }

    // Step 2: Check QE Identity
    let qe_id_type: EnclaveIdType;
    if tee_type == TDX_TEE_TYPE {
        qe_id_type = EnclaveIdType::TDQE
    } else {
        qe_id_type = EnclaveIdType::QE
    }

    let qe_id_string = match qe_id_type {
        EnclaveIdType::QE => "qe",
        EnclaveIdType::QVE => "qve",
        EnclaveIdType::TDQE => "td",
    };

    match get_enclave_identity(
        provider,
        deployment_version,
        qe_id_type,
        PCS_API_VERSION,
        tcb_eval_num,
    )
    .await
    {
        Ok(qe_id_content) => {
            let qe_id_str =
                std::str::from_utf8(&qe_id_content).expect("QE identity is not valid UTF-8");
            if collateral_is_outdated(qe_id_str, "enclaveIdentity") {
                missing.push(MissingCollateral::QEIdentity(
                    qe_id_string.to_string(),
                    PCS_API_VERSION,
                ));
            } else {
                if print {
                    let qe_id_filename =
                        format!("identity-{}-v{}.json", qe_id_string, PCS_API_VERSION);
                    print_str_content(&qe_id_filename, &qe_id_str).unwrap();
                }
                ret.qe_identity = qe_id_str.to_string();
            }
        }
        _ => {
            missing.push(MissingCollateral::QEIdentity(
                qe_id_string.to_string(),
                PCS_API_VERSION,
            ));
        }
    }

    // Step 3: get the fmspc value and the pck ca using dcap-rs
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
    let pck_issuer = pck_cert_chain.pck_cert_chain[0]
        .tbs_certificate
        .issuer
        .to_string();

    let pck_type = if pck_issuer.contains(constants::INTEL_PCK_PLATFORM_CA_CN) {
        CA::PLATFORM
    } else if pck_issuer.contains(constants::INTEL_PCK_PROCESSOR_CA_CN) {
        CA::PROCESSOR
    } else {
        return Err(CollateralError::Validation(format!(
            "Unknown PCK Issuer: {}",
            pck_issuer
        )));
    };

    // Step 4: Check TCBInfo
    let tcb_type: u8;
    if tee_type == TDX_TEE_TYPE {
        tcb_type = 1;
    } else {
        tcb_type = 0;
    }
    match get_tcb_info(
        provider,
        deployment_version,
        tcb_type,
        fmspc.as_str(),
        TCB_VERSION,
        tcb_eval_num,
    )
    .await
    {
        Ok(tcb_content) => {
            let tcb_str = std::str::from_utf8(&tcb_content).expect("TCB info is not valid UTF-8");
            if collateral_is_outdated(tcb_str, "tcbInfo") {
                missing.push(MissingCollateral::FMSPCTCB(
                    tcb_type,
                    fmspc.clone(),
                    TCB_VERSION,
                ));
            } else {
                let tcb_type_str: &str = match tcb_type {
                    0 => "sgx",
                    1 => "tdx",
                    _ => unreachable!(),
                };
                if print {
                    let tcb_filename = format!("tcbinfo-{}-v{}.json", tcb_type_str, TCB_VERSION);
                    print_str_content(&tcb_filename, &tcb_str).unwrap();
                }
                ret.tcb_info = tcb_str.to_string();
            }
        }
        _ => {
            missing.push(MissingCollateral::FMSPCTCB(
                tcb_type,
                fmspc.clone(),
                TCB_VERSION,
            ));
        }
    }

    // Step 5: Check TCB Signing CA is present
    match get_certificate_by_id(provider, deployment_version, CA::SIGNING).await {
        Ok((signing_ca, _)) => {
            if signing_ca.len() == 0 {
                missing.push(MissingCollateral::PCS(
                    INTEL_TCB_SIGNING_CA_CN.to_string(),
                    true,
                    false,
                ));
            } else {
                let signing_ca_cert = parse_x509_der(&signing_ca);
                if !signing_ca_cert.validity.is_valid() {
                    missing.push(MissingCollateral::PCS(
                        INTEL_TCB_SIGNING_CA_CN.to_string(),
                        true,
                        false,
                    ));
                } else {
                    if print {
                        print_content("signingca.der", &signing_ca).unwrap();
                    }
                    ret.tcb_signing_ca = signing_ca;
                }
            }
        }
        _ => {
            missing.push(MissingCollateral::PCS(
                INTEL_TCB_SIGNING_CA_CN.to_string(),
                true,
                false,
            ));
        }
    }

    // Step 6: Check PCK CA CRLs
    let pck_type_str = match pck_type {
        CA::PLATFORM => INTEL_PCK_PLATFORM_CA_CN,
        CA::PROCESSOR => INTEL_PCK_PROCESSOR_CA_CN,
        _ => unreachable!(),
    };

    match get_certificate_by_id(provider, deployment_version, pck_type).await {
        Ok((pck_ca_cert, pck_ca_crl)) => {
            if pck_ca_cert.len() == 0 {
                missing.push(MissingCollateral::PCS(
                    pck_type_str.to_string(),
                    true,
                    false,
                ));
            } else if pck_ca_crl.len() == 0 {
                missing.push(MissingCollateral::PCS(
                    pck_type_str.to_string(),
                    false,
                    true,
                ));
            } else {
                if print {
                    let pck_filename = format!("{}.der", pck_type_str);
                    let pck_crl_filename = format!("{}-crl.der", pck_type_str);
                    print_content(&pck_filename, &pck_ca_cert).unwrap();
                    print_content(&pck_crl_filename, &pck_ca_crl).unwrap();
                }
                let pck_cert_parsed = parse_x509_der(&pck_ca_cert);
                if !pck_cert_parsed.validity.is_valid() {
                    missing.push(MissingCollateral::PCS(
                        pck_type_str.to_string(),
                        true,
                        false,
                    ));
                } else {
                    let pck_ca_crl_parsed = parse_crl_der(&pck_ca_crl);
                    if let Some(next_update) = pck_ca_crl_parsed.next_update() {
                        let now = x509_parser::time::ASN1Time::now();
                        if next_update < now {
                            missing.push(MissingCollateral::PCS(
                                pck_type_str.to_string(),
                                false,
                                true,
                            ));
                        }
                    }
                    ret.pck_crl = pck_ca_crl;
                }
            }
        }
        _ => {
            missing.push(MissingCollateral::PCS(pck_type_str.to_string(), true, true));
        }
    }

    // Return result based on missing collaterals
    if missing.is_empty() {
        Ok(ret)
    } else {
        Err(CollateralError::Missing(MissingCollateralReport::new(
            missing,
        )))
    }
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
/// # Panics
///
/// Panics if the DER encoding is invalid
pub fn parse_x509_der<'a>(raw_bytes: &'a [u8]) -> X509Certificate<'a> {
    let (_, cert) = X509Certificate::from_der(raw_bytes).unwrap();
    cert
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
/// # Panics
///
/// Panics if the DER encoding is invalid
pub fn parse_crl_der<'a>(raw_bytes: &'a [u8]) -> CertificateRevocationList<'a> {
    let (_, crl) = CertificateRevocationList::from_der(raw_bytes).unwrap();
    crl
}

#[cfg(test)]
mod test {
    use super::*;
    use automata_dcap_network_registry::Network;

    fn get_default_provider() -> impl Provider {
        let provider =
            Network::create_provider(&Network::default_network(None).unwrap(), None, None)
                .expect("Failed to get provider from default network");
        provider
    }

    #[tokio::test]
    async fn test_v3() {
        let cargo_manifest_dir = env!("CARGO_MANIFEST_DIR");
        let quote_path = format!("{}/../../samples/quotev3.hex", cargo_manifest_dir);
        let quote_hex = std::fs::read_to_string(quote_path.as_str()).unwrap();
        let quote = hex::decode(quote_hex.trim()).unwrap();

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
        let cargo_manifest_dir = env!("CARGO_MANIFEST_DIR");
        let quote_path = format!("{}/../../samples/quotev4.hex", cargo_manifest_dir);
        let quote_hex = std::fs::read_to_string(quote_path.as_str()).unwrap();
        let quote = hex::decode(quote_hex.trim()).unwrap();
        let res =
            find_missing_collaterals_from_quote(&get_default_provider(), None, &quote, false, None)
                .await
                .unwrap();

        println!("{:?}", res);
    }
}
