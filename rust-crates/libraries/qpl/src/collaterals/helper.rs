use super::cloud_providers::*;
use super::contracts::*;
use super::pccs_types::*;
use alloy::primitives::Bytes;
use alloy::providers::Provider;
use automata_dcap_evm_bindings::r#i_fmspc_tcb_dao::IFmspcTcbDao;
use automata_dcap_evm_bindings::r#i_fmspc_tcb_dao::IFmspcTcbDao::TcbInfoJsonObj;
use automata_dcap_evm_bindings::r#i_pcs_dao::IPcsDao;
use automata_dcap_network_registry::Network;
use automata_dcap_utils::Version;
use crate::types::*;
use openssl::x509::X509Crl;
use pccs_reader_rs::*;
use reqwest;
use std::ffi::{c_char, CStr, CString};

const INTEL_PCS_SUBSCRIPTION_KEY_ENV: &str = "INTEL_PCS_SUBSCRIPTION_KEY";

fn get_intel_pcs_subscription_key() -> String {
    match std::env::var(INTEL_PCS_SUBSCRIPTION_KEY_ENV) {
        Ok(v) => v,
        Err(_) => {
            println!("[ERROR] pleause configure the intel pcs subscription key");
            String::new()
        }
    }
}

pub fn upload_missing_collaterals<P: Provider>(
    provider: &P,
    deployment_version: Option<Version>,
    quote: &[u8],
    pccs_url: String,
    tcb_eval_num: Option<u32>,
) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    // Derive network from provider
    let network = rt.block_on(async {
        Network::from_provider(provider, deployment_version).await
    }).expect("Failed to derive network from provider");
    let missing_collateral_result = rt.block_on(
        pccs_reader_rs::find_missing_collaterals_from_quote(&provider, deployment_version, quote, false, tcb_eval_num),
    );

    let missing_report = match missing_collateral_result {
        Ok(_collaterals) => {
            println!("All collaterals are present!");
            return;
        }
        Err(pccs_reader_rs::CollateralError::Missing(report)) => report,
        Err(pccs_reader_rs::CollateralError::Validation(msg)) => {
            println!("Validation error: {}", msg);
            return;
        }
    };

    println!("Found {} missing collateral(s)", missing_report.len());
    println!("{}", missing_report);

    // Process all missing collaterals
    for missing_collateral in missing_report.iter() {
        println!("Uploading: {}", missing_collateral);
        match missing_collateral {
            MissingCollateral::QEIdentity(enclave_id_str, quote_version) => {
                let (enclave_id, enclave_id_type) = if enclave_id_str == "td" {
                    (EnclaveID::TD_QE, "tdx".to_string())
                } else {
                    (EnclaveID::QE, "sgx".to_string())
                };
                let collateral_version = if *quote_version == 3 {
                    "v3".to_string()
                } else {
                    "v4".to_string()
                };
                let req_url = format!(
                    "{}/{}/certification/{}/qe/identity",
                    pccs_url, enclave_id_type, collateral_version
                );
                let response = match rt.block_on(reqwest::get(req_url.clone())) {
                    Ok(v) => v,
                    Err(_) => {
                        println!("Unable to get {}", req_url);
                        return;
                    }
                };
                if response.status().is_success() {
                    let headers = response.headers();
                    let enclave_identity_issuer_chains_str =
                        if let Some(cert) = headers.get("SGX-Enclave-Identity-Issuer-Chain") {
                            cert.to_str().unwrap().to_string()
                        } else {
                            println!(
                                "Cannot find SGX-Enclave-Identity-Issuer-Chain in {:?}, exit",
                                req_url
                            );
                            return;
                        };
                    let enclave_identity_issuer_chains_str =
                        urlencoding::decode(&enclave_identity_issuer_chains_str)
                            .expect("Invalid UTF-8");
                    let enclave_identity_issuer_chains_str =
                        enclave_identity_issuer_chains_str.to_string();
                    let qe_identity_str = match rt.block_on(response.text()) {
                        Ok(v) => v,
                        Err(_) => {
                            println!("Unable to get the content of {}", req_url);
                            return;
                        }
                    };
                    println!(
                        "Enclave-Identity-Issuer-Chain: {}",
                        enclave_identity_issuer_chains_str
                    );
                    println!("QE-Identity: {}", qe_identity_str);

                    upsert_enclave_identity(
                        provider,
                        network,
                        enclave_id,
                        collateral_version,
                        qe_identity_str.as_str(),
                        enclave_identity_issuer_chains_str.as_str(),
                        tcb_eval_num,
                    )
                }
            }
            MissingCollateral::FMSPCTCB(tcb_type, fmspc, tcb_version) => {
                let tcb_type_str = if *tcb_type == 1 {
                    "tdx".to_string()
                } else {
                    "sgx".to_string()
                };
                let collateral_version = if *tcb_version == 2 {
                    "v3".to_string()
                } else {
                    "v4".to_string()
                };
                let req_url = format!(
                    "{}/{}/certification/{}/tcb?fmspc={}",
                    pccs_url, tcb_type_str, collateral_version, fmspc
                );
                println!("req_url: {:?}", req_url);
                let response = match rt.block_on(reqwest::get(req_url.clone())) {
                    Ok(v) => v,
                    Err(_) => {
                        println!("Unable to get {}", req_url);
                        return;
                    }
                };
                let tcb_info_str = if response.status().is_success() {
                    let headers = response.headers();
                    // v3
                    if let Some(cert) = headers.get("SGX-TCB-Info-Issuer-Chain") {
                        println!("SGX-TCB-Info-Issuer-Chain: {:?}", cert);
                    }
                    // v4
                    if let Some(cert) = headers.get("TCB-Info-Issuer-Chain") {
                        println!("TCB-Info-Issuer-Chain: {:?}", cert);
                    }
                    let content = match rt.block_on(response.text()) {
                        Ok(v) => v,
                        Err(_) => {
                            println!("Unable to get the content of {}", req_url);
                            return;
                        }
                    };
                    println!("TCB-Info: {}", content);
                    content
                } else {
                    println!("[ERROR] {} returns {:?}, exit", req_url, response.status());
                    return;
                };
                // TCB Info
                let tcb_info: TcbInfo = serde_json::from_str(&tcb_info_str).unwrap();
                let tcb_info_str = &tcb_info_str[r#""tcbInfo":{"#.len()..];
                let end_idx = tcb_info_str.find(r#","signature""#).unwrap();
                let tcb_info_str = &tcb_info_str[..end_idx];
                let signature_bytes: Bytes = tcb_info.signature.parse().unwrap();
                let tcb_info_obj = TcbInfoJsonObj {
                    tcbInfoStr: tcb_info_str.to_string(),
                    signature: signature_bytes,
                };
                println!("tcb_info_obj.tcb_info_str: {}", tcb_info_obj.tcbInfoStr);
                println!("tcb_info_obj.signature: {:?}", tcb_info_obj.signature);

                // Determine tcb_id from tcb_type string
                let tcb_id_u8 = if tcb_type_str == "tdx" { 1 } else { 0 };

                let fmspc_tcb_dao_address = rt.block_on(async {
                    network.resolve_contract_address(
                        automata_dcap_network_registry::ContractKind::FmspcTcbDao,
                        tcb_eval_num,
                        Some(tcb_id_u8),
                    ).await
                }).unwrap();
                let fmspc_tcb_dao = IFmspcTcbDao::new(fmspc_tcb_dao_address, &provider);
                match rt.block_on(
                    fmspc_tcb_dao
                        .upsertFmspcTcb(tcb_info_obj)
                        .gas_price(network.gas_price_hint_wei().unwrap_or(10000u128))
                        .send(),
                ) {
                    Ok(pending_tx) => {
                        let tx_hash = *pending_tx.tx_hash();
                        println!("txn[upsert_fmspc_tcb] hash: {:?}", tx_hash);
                        match rt.block_on(pending_tx.watch()) {
                            Ok(receipt) => {
                                println!("txn[upsert_fmspc_tcb] receipt: {:?}", receipt);
                            }
                            Err(err) => {
                                println!("txn[upsert_fmspc_tcb] receipt meet error: {:?}", err);
                            }
                        }
                    }
                    Err(err) => {
                        println!("txn[upsert_fmspc_tcb] meet error: {:?}", err);
                    }
                }
            }
            MissingCollateral::PCS(pck_ca_str, _, _) => {
                let (pck_ca, pck) = if pck_ca_str.contains("Processor") {
                    ("processor".to_string(), CAID::Processor)
                } else if pck_ca_str.contains("Platform") {
                    ("platform".to_string(), CAID::Platform)
                } else {
                    // should not happen because it's already included in the tcb/qe cert chain
                    continue;
                };
                let req_url = format!(
                    "{}/sgx/certification/v3/pckcrl?ca={}",
                    pccs_url,
                    pck_ca.clone()
                );
                let response = match rt.block_on(reqwest::get(req_url.clone())) {
                    Ok(v) => v,
                    Err(_) => {
                        println!("Unable to get {}", req_url);
                        return;
                    }
                };
                let pck_crl = if response.status().is_success() {
                    let headers = response.headers();
                    if let Some(cert) = headers.get("SGX-PCK-CRL-Issuer-Chain") {
                        println!("SGX-PCK-CRL-Issuer-Chain: {:?}", cert);
                    }
                    let content = match rt.block_on(response.text()) {
                        Ok(v) => v,
                        Err(_) => {
                            println!("Unable to get the content of {}", req_url);
                            return;
                        }
                    };
                    println!("SGX-PCK-CRL: {}", content);
                    content
                } else {
                    println!("[ERROR] {} returns {:?}, exit", req_url, response.status());
                    return;
                };
                let pcs_dao = IPcsDao::new(network.contracts.pccs.pcs_dao, provider);
                // PCK CRL
                let pck_crl = match X509Crl::from_pem(pck_crl.as_bytes()) {
                    Ok(c) => hex::encode(c.to_der().unwrap()),
                    Err(err) => {
                        println!("Error parsing certificate: {:?}", err);
                        return;
                    }
                };
                let pck_crl_bytes = Bytes::from(hex::decode(&pck_crl).unwrap());
                match rt.block_on(
                    pcs_dao
                        .upsertPckCrl(pck as u8, pck_crl_bytes)
                        .gas_price(network.gas_price_hint_wei().unwrap_or(10000u128))
                        .send(),
                ) {
                    Ok(pending_tx) => {
                        let tx_hash = *pending_tx.tx_hash();
                        println!("txn[upsert_pck_crl] hash: {:?}", tx_hash);
                        match rt.block_on(pending_tx.watch()) {
                            Ok(receipt) => {
                                println!("txn[upsert_pck_crl] receipt: {:?}", receipt);
                            }
                            Err(err) => {
                                println!("txn[upsert_pck_crl] receipt meet error: {:?}", err);
                            }
                        }
                    }
                    Err(err) => {
                        println!("txn[upsert_pck_crl] meet error: {:?}", err);
                    }
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn sgx_ql_get_quote_config<P: Provider>(
    provider: &P,
    deployment_version: Option<Version>,
    pck_cert_id: SgxQlPckCertId,
    data_source: DataSource,
    collateral_version: String,
    pccs_url: String,
) {
    // Derive network from provider
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let network = rt.block_on(async {
        Network::from_provider(provider, deployment_version).await
    }).expect("Failed to derive network from provider");

    println!("pck_cert_id: {:?}", pck_cert_id);

    println!("cpu_svn: {:?}", unsafe { *pck_cert_id.p_platform_cpu_svn });
    println!("pce_svn: {:?}", unsafe {
        *pck_cert_id.p_platform_pce_isv_svn
    });

    let cpu_svn = unsafe { *pck_cert_id.p_platform_cpu_svn };
    let pce_svn = unsafe { *pck_cert_id.p_platform_pce_isv_svn };

    println!("cpu_svn: {:?}", hex::encode(cpu_svn.cpu_svn));
    println!("pce_svn: {:?}", hex::encode(pce_svn.isv_svn.to_le_bytes()));
    println!(
        "pce_id: {:?}",
        hex::encode(pck_cert_id.pce_id.to_le_bytes())
    );
    let qe_id = unsafe {
        std::slice::from_raw_parts(pck_cert_id.p_qe3_id, pck_cert_id.qe3_id_size as usize)
    };
    println!("qe_id: {:?}", hex::encode(qe_id));
    let encrypted_ppid = unsafe {
        std::slice::from_raw_parts(
            pck_cert_id.p_encrypted_ppid,
            pck_cert_id.encrypted_ppid_size as usize,
        )
    };
    println!("encrypted_ppid: {:?}", hex::encode(encrypted_ppid));
    let qe_id_str = hex::encode(qe_id);
    let cpu_svn_str = hex::encode(unsafe { *pck_cert_id.p_platform_cpu_svn }.cpu_svn);
    let pce_svn_str = hex::encode(
        unsafe { *pck_cert_id.p_platform_pce_isv_svn }
            .isv_svn
            .to_le_bytes(),
    );
    let pce_id_str = hex::encode(pck_cert_id.pce_id.to_le_bytes());

    if data_source == DataSource::All || data_source == DataSource::Azure {
        std::env::set_var("AZDCAP_COLLATERAL_VERSION", collateral_version.clone());
        let p_pck_cert_id: *const SgxQlPckCertId = &pck_cert_id as *const SgxQlPckCertId;
        let mut sgx_ql_config: SgxQlConfig =
            SgxQlConfig::new([0_u8; 16], 0, std::ptr::null_mut(), 0);
        let mut p_sgx_ql_config: *mut SgxQlConfig = &mut sgx_ql_config as *mut SgxQlConfig;
        let pp_sgx_ql_config: *mut *mut SgxQlConfig = &mut p_sgx_ql_config as *mut *mut SgxQlConfig;
        let ret = azure::az_dcap_sgx_ql_get_quote_config(p_pck_cert_id, pp_sgx_ql_config);
        println!("azure dcap sgx_ql_get_quote_config func: {:?}", ret);
        let quote_config = unsafe { *pp_sgx_ql_config };
        unsafe { quote_config.as_ref().unwrap().print() };

        let tcbm = unsafe {
            let mut tcbm_vec = Vec::new();
            let mut tcbm_cpu_svn = quote_config
                .as_ref()
                .unwrap()
                .cert_cpu_svn
                .cpu_svn
                .clone()
                .to_vec();
            tcbm_vec.append(&mut tcbm_cpu_svn);
            let tcbm_pce_svn = quote_config.as_ref().unwrap().cert_pce_isv_svn.isv_svn;
            let mut tcbm_pce_svn = tcbm_pce_svn.to_le_bytes().to_vec();
            tcbm_vec.append(&mut tcbm_pce_svn);
            hex::encode(tcbm_vec)
        };
        let cert_data = unsafe {
            std::slice::from_raw_parts(
                quote_config.as_ref().unwrap().cert_data,
                quote_config.as_ref().unwrap().cert_data_size as usize,
            )
        };
        let cert_data = std::str::from_utf8(cert_data).unwrap();
        upsert_pck_cert(
            provider,
            network,
            CAID::Platform,
            qe_id_str,
            pce_id_str,
            cpu_svn_str,
            pce_svn_str,
            tcbm,
            cert_data,
        );

        let ret = azure::az_dcap_sgx_ql_free_quote_config(quote_config);
        println!("azure dcap sgx_ql_free_quote_config func: {:?}", ret);
    }
    if data_source == DataSource::All || data_source == DataSource::Local {
        // Ref: https://download.01.org/intel-sgx/sgx-dcap/1.19/linux/docs/SGX_DCAP_Caching_Service_Design_Guide.pdf || 3.1 Section
        let encrypted_ppid = if !encrypted_ppid.is_empty() {
            hex::encode(encrypted_ppid)
        } else {
            hex::encode([0; 384])
        };
        let req_url = format!(
            "{}/sgx/certification/{}/pckcert",
            pccs_url,
            collateral_version.clone(),
        );
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let client = reqwest::Client::new();
        let query_params = vec![
            ("cpusvn".to_string(), hex::encode(cpu_svn.cpu_svn)),
            (
                "pcesvn".to_string(),
                hex::encode(pce_svn.isv_svn.to_le_bytes()),
            ),
            (
                "pceid".to_string(),
                hex::encode(pck_cert_id.pce_id.to_le_bytes()),
            ),
            ("encrypted_ppid".to_string(), encrypted_ppid),
        ];
        let mut req_builder = client.get(req_url.clone()).query(&query_params);
        if collateral_version == "v3" {
            let intel_pcs_subscription_key = get_intel_pcs_subscription_key();
            if intel_pcs_subscription_key.is_empty() {
                return;
            }
            let intel_pcs_subscription_key_str = intel_pcs_subscription_key.as_str();
            req_builder =
                req_builder.header("Ocp-Apim-Subscription-Key", intel_pcs_subscription_key_str);
        }
        let response = match rt.block_on(req_builder.send()) {
            Ok(v) => v,
            Err(_) => {
                println!("Unable to get {}", req_url);
                return;
            }
        };
        if response.status().is_success() {
            let headers = response.headers();
            if let Some(cert) = headers.get("SGX-PCK-Certificate-Issuer-Chain") {
                println!("cert: {:?}", cert);
            }
            if let Some(tcbm) = headers.get("SGX-TCBm") {
                println!("tcbm: {:?}", tcbm);
            }
            let content = match rt.block_on(response.text()) {
                Ok(v) => v,
                Err(_) => {
                    println!("Unable to get the content of {}", req_url);
                    return;
                }
            };
            println!("SGX-PCK-Cert: {:?}", content);
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn sgx_ql_get_quote_verification_collateral<P: Provider>(
    provider: &P,
    deployment_version: Option<Version>,
    fmspc: String,
    pck_ca: String,
    data_source: DataSource,
    collateral_version: String,
    pccs_url: String,
    all_verification_collateral: u64,
) {
    // Derive network from provider
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let network = rt.block_on(async {
        Network::from_provider(provider, deployment_version).await
    }).expect("Failed to derive network from provider");

    let pck_id = if pck_ca == "platform" {
        CAID::Platform
    } else {
        CAID::Processor
    };
    let enclave_id = EnclaveID::QE;

    if data_source == DataSource::All || data_source == DataSource::Azure {
        std::env::set_var("AZDCAP_COLLATERAL_VERSION", collateral_version.clone());
        let fmspc_slices =
            hex::decode(fmspc.trim_start_matches("0x")).expect("Failed to decode hex string");
        let fmspc_size = fmspc_slices.len() as u16;
        println!(
            "fmspc_slices: {:?}, fmspc_size: {:?}",
            fmspc_slices, fmspc_size
        );
        let fmspc_pointer = fmspc_slices.as_ptr();
        let pck_ca_c_string = CString::new(pck_ca.clone()).expect("CString conversion failed");
        let pck_ca_pointer = pck_ca_c_string.as_ptr();
        let mut p_quote_collateral: *mut SgxQlQveCollateral = std::ptr::null_mut();
        let pp_quote_collateral: *mut *mut SgxQlQveCollateral =
            &mut p_quote_collateral as *mut *mut SgxQlQveCollateral;
        let ret = azure::az_dcap_sgx_ql_get_quote_verification_collateral(
            fmspc_pointer,
            fmspc_size,
            pck_ca_pointer,
            pp_quote_collateral,
        );
        println!(
            "azure dcap sgx_ql_get_quote_verification_collateral func: {:?}",
            ret
        );
        let p_quote_collateral = unsafe { *pp_quote_collateral };
        unsafe { p_quote_collateral.as_ref().unwrap().print() };

        let root_ca_crl = unsafe {
            std::slice::from_raw_parts(
                p_quote_collateral.as_ref().unwrap().root_ca_crl,
                p_quote_collateral.as_ref().unwrap().root_ca_crl_size as usize,
            )
        };
        let root_ca_crl: Vec<u8> = root_ca_crl.iter().map(|&x| x as u8).collect();
        let root_ca_crl = std::str::from_utf8(&root_ca_crl).unwrap();
        let pck_crl = unsafe {
            std::slice::from_raw_parts(
                p_quote_collateral.as_ref().unwrap().pck_crl,
                p_quote_collateral.as_ref().unwrap().pck_crl_size as usize,
            )
        };
        let pck_crl: Vec<u8> = pck_crl.iter().map(|&x| x as u8).collect();
        let pck_crl = std::str::from_utf8(&pck_crl)
            .unwrap()
            .trim_end_matches("\0");
        let tcb_info_str = unsafe {
            std::slice::from_raw_parts(
                p_quote_collateral.as_ref().unwrap().tcb_info,
                p_quote_collateral.as_ref().unwrap().tcb_info_size as usize,
            )
        };
        let tcb_info_str: Vec<u8> = tcb_info_str.iter().map(|&x| x as u8).collect();
        let tcb_info_str = std::str::from_utf8(&tcb_info_str)
            .unwrap()
            .trim_end_matches("\0");
        let enclave_identity_str = unsafe {
            std::slice::from_raw_parts(
                p_quote_collateral.as_ref().unwrap().qe_identity,
                p_quote_collateral.as_ref().unwrap().qe_identity_size as usize,
            )
        };
        let enclave_identity_str: Vec<u8> = enclave_identity_str.iter().map(|&x| x as u8).collect();
        let enclave_identity_str = std::str::from_utf8(&enclave_identity_str)
            .unwrap()
            .trim_end_matches("\0");
        let enclave_identity_issuer_chains_str = unsafe {
            std::slice::from_raw_parts(
                p_quote_collateral
                    .as_ref()
                    .unwrap()
                    .qe_identity_issuer_chain,
                p_quote_collateral
                    .as_ref()
                    .unwrap()
                    .qe_identity_issuer_chain_size as usize,
            )
        };
        let enclave_identity_issuer_chains_str: Vec<u8> = enclave_identity_issuer_chains_str
            .iter()
            .map(|&x| x as u8)
            .collect();
        let enclave_identity_issuer_chains_str =
            std::str::from_utf8(&enclave_identity_issuer_chains_str)
                .unwrap()
                .trim_end_matches("\0");
        println!("root_ca_crl: {}", root_ca_crl);
        println!("pck_crl: {}", pck_crl);
        println!("tcb_info_str: {:?}", tcb_info_str);
        println!("enclave_identity_str: {:?}", enclave_identity_str);
        println!(
            "enclave_identity_issuer_chains_str: {}",
            enclave_identity_issuer_chains_str
        );
        update_verification_collateral(
            provider,
            network,
            Some(root_ca_crl),
            pck_id,
            pck_crl,
            tcb_info_str,
            enclave_id,
            collateral_version.clone(),
            enclave_identity_str,
            enclave_identity_issuer_chains_str,
            all_verification_collateral,
            None,
        );

        let ret = azure::az_dcap_sgx_ql_free_quote_verification_collateral(p_quote_collateral);
        println!(
            "azure dcap sgx_ql_free_quote_verification_collateral func: {:?}",
            ret
        );
    }
    if data_source == DataSource::All || data_source == DataSource::Local {
        // Ref: https://download.01.org/intel-sgx/sgx-dcap/1.19/linux/docs/SGX_DCAP_Caching_Service_Design_Guide.pdf || 3.2 Section Get PCK Cert CRL
        let req_url = format!(
            "{}/sgx/certification/{}/pckcrl?ca={}",
            pccs_url,
            collateral_version.clone(),
            pck_ca.clone()
        );
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let response = match rt.block_on(reqwest::get(req_url.clone())) {
            Ok(v) => v,
            Err(_) => {
                println!("Unable to get {}", req_url);
                return;
            }
        };
        let pck_crl = if response.status().is_success() {
            let headers = response.headers();
            if let Some(cert) = headers.get("SGX-PCK-CRL-Issuer-Chain") {
                println!("SGX-PCK-CRL-Issuer-Chain: {:?}", cert);
            }
            let content = match rt.block_on(response.text()) {
                Ok(v) => v,
                Err(_) => {
                    println!("Unable to get the content of {}", req_url);
                    return;
                }
            };
            println!("SGX-PCK-CRL: {}", content);
            content
        } else {
            println!("[ERROR] {} returns {:?}, exit", req_url, response.status());
            #[allow(clippy::needless_return)]
            return;
        };
        // Ref: https://download.01.org/intel-sgx/sgx-dcap/1.19/linux/docs/SGX_DCAP_Caching_Service_Design_Guide.pdf || 3.7 Section Get Root CA CRL
        // This API endpoint is not found in Intel PCS: https://api.portal.trustedservices.intel.com/content/documentation.html
        // let req_url = format!(
        //     "{}/sgx/certification/{}/rootcacrl",
        //     pccs_url,
        //     collateral_version.clone()
        // );
        // let rt = tokio::runtime::Builder::new_current_thread()
        //     .enable_all()
        //     .build()
        //     .unwrap();
        // let response = match rt.block_on(reqwest::get(req_url.clone())) {
        //     Ok(v) => v,
        //     Err(_) => {
        //         println!("Unable to get {}", req_url);
        //         return;
        //     }
        // };
        // if response.status().is_success() {
        //     let content = match rt.block_on(response.text()) {
        //         Ok(v) => v,
        //         Err(_) => {
        //             println!("Unable to get the content of {}", req_url);
        //             return;
        //         }
        //     };
        //     println!("SGX-Root-CA-Crl: {:?}", content);
        // }
        // Ref: https://download.01.org/intel-sgx/sgx-dcap/1.19/linux/docs/SGX_DCAP_Caching_Service_Design_Guide.pdf || 3.3 Section Get TCB Info
        let req_url = format!(
            "{}/sgx/certification/{}/tcb?fmspc={}",
            pccs_url,
            collateral_version.clone(),
            fmspc
        );
        println!("req_url: {:?}", req_url);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let response = match rt.block_on(reqwest::get(req_url.clone())) {
            Ok(v) => v,
            Err(_) => {
                println!("Unable to get {}", req_url);
                return;
            }
        };
        let tcb_info_str = if response.status().is_success() {
            let headers = response.headers();
            // v3
            if let Some(cert) = headers.get("SGX-TCB-Info-Issuer-Chain") {
                println!("SGX-TCB-Info-Issuer-Chain: {:?}", cert);
            }
            // v4
            if let Some(cert) = headers.get("TCB-Info-Issuer-Chain") {
                println!("TCB-Info-Issuer-Chain: {:?}", cert);
            }
            let content = match rt.block_on(response.text()) {
                Ok(v) => v,
                Err(_) => {
                    println!("Unable to get the content of {}", req_url);
                    return;
                }
            };
            println!("TCB-Info: {}", content);
            content
        } else {
            println!("[ERROR] {} returns {:?}, exit", req_url, response.status());
            #[allow(clippy::needless_return)]
            return;
        };
        // Ref: https://download.01.org/intel-sgx/sgx-dcap/1.19/linux/docs/SGX_DCAP_Caching_Service_Design_Guide.pdf || 3.4 Section Get QE Identity
        let req_url = format!(
            "{}/sgx/certification/{}/qe/identity",
            pccs_url,
            collateral_version.clone()
        );
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let response = match rt.block_on(reqwest::get(req_url.clone())) {
            Ok(v) => v,
            Err(_) => {
                println!("Unable to get {}", req_url);
                return;
            }
        };
        if response.status().is_success() {
            let headers = response.headers();
            let enclave_identity_issuer_chains_str =
                if let Some(cert) = headers.get("SGX-Enclave-Identity-Issuer-Chain") {
                    cert.to_str().unwrap().to_string()
                } else {
                    println!(
                        "Cannot find SGX-Enclave-Identity-Issuer-Chain in {:?}, exit",
                        req_url
                    );
                    return;
                };
            let enclave_identity_issuer_chains_str =
                urlencoding::decode(&enclave_identity_issuer_chains_str).expect("Invalid UTF-8");
            let enclave_identity_issuer_chains_str = enclave_identity_issuer_chains_str.to_string();
            let qe_identity_str = match rt.block_on(response.text()) {
                Ok(v) => v,
                Err(_) => {
                    println!("Unable to get the content of {}", req_url);
                    return;
                }
            };
            println!(
                "SGX-Enclave-Identity-Issuer-Chain: {}",
                enclave_identity_issuer_chains_str
            );
            println!("SGX-QE-Identity: {}", qe_identity_str);

            update_verification_collateral(
                provider,
                network,
                None,
                pck_id,
                pck_crl.as_str(),
                tcb_info_str.as_str(),
                enclave_id,
                collateral_version.clone(),
                qe_identity_str.as_str(),
                enclave_identity_issuer_chains_str.as_str(),
                all_verification_collateral,
                None,
            );
        } else {
            println!("[ERROR] {} returns {:?}, exit", req_url, response.status());
            #[allow(clippy::needless_return)]
            return;
        };
    }
}

#[allow(clippy::too_many_arguments)]
pub fn tdx_ql_get_quote_verification_collateral<P: Provider>(
    provider: &P,
    deployment_version: Option<Version>,
    fmspc: String,
    pck_ca: String,
    data_source: DataSource,
    collateral_version: String,
    pccs_url: String,
    all_verification_collateral: u64,
) {
    // Derive network from provider
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let network = rt.block_on(async {
        Network::from_provider(provider, deployment_version).await
    }).expect("Failed to derive network from provider");

    let pck_id = if pck_ca == "platform" {
        CAID::Platform
    } else {
        CAID::Processor
    };
    let enclave_id = EnclaveID::TD_QE;

    if data_source == DataSource::All || data_source == DataSource::Azure {
        std::env::set_var("AZDCAP_COLLATERAL_VERSION", collateral_version.clone());
        let fmspc_slices =
            hex::decode(fmspc.trim_start_matches("0x")).expect("Failed to decode hex string");
        let fmspc_size = fmspc_slices.len() as u16;
        println!(
            "fmspc_slices: {:?}, fmspc_size: {:?}",
            fmspc_slices, fmspc_size
        );
        let fmspc_pointer = fmspc_slices.as_ptr();
        let pck_ca_c_string = CString::new(pck_ca.clone()).expect("CString conversion failed");
        let pck_ca_pointer = pck_ca_c_string.as_ptr();
        let mut p_quote_collateral: *mut SgxQlQveCollateral = std::ptr::null_mut();
        let pp_quote_collateral: *mut *mut SgxQlQveCollateral =
            &mut p_quote_collateral as *mut *mut SgxQlQveCollateral;
        let ret = azure::az_dcap_tdx_ql_get_quote_verification_collateral(
            fmspc_pointer,
            fmspc_size,
            pck_ca_pointer,
            pp_quote_collateral,
        );
        println!(
            "azure dcap tdx_ql_get_quote_verification_collateral func: {:?}",
            ret
        );
        let p_quote_collateral = unsafe { *pp_quote_collateral };
        unsafe { p_quote_collateral.as_ref().unwrap().print() };

        let root_ca_crl = unsafe {
            std::slice::from_raw_parts(
                p_quote_collateral.as_ref().unwrap().root_ca_crl,
                p_quote_collateral.as_ref().unwrap().root_ca_crl_size as usize,
            )
        };
        let root_ca_crl: Vec<u8> = root_ca_crl.iter().map(|&x| x as u8).collect();
        let root_ca_crl = std::str::from_utf8(&root_ca_crl).unwrap();
        let pck_crl = unsafe {
            std::slice::from_raw_parts(
                p_quote_collateral.as_ref().unwrap().pck_crl,
                p_quote_collateral.as_ref().unwrap().pck_crl_size as usize,
            )
        };
        let pck_crl: Vec<u8> = pck_crl.iter().map(|&x| x as u8).collect();
        let pck_crl = std::str::from_utf8(&pck_crl)
            .unwrap()
            .trim_end_matches("\0");
        let tcb_info_str = unsafe {
            std::slice::from_raw_parts(
                p_quote_collateral.as_ref().unwrap().tcb_info,
                p_quote_collateral.as_ref().unwrap().tcb_info_size as usize,
            )
        };
        let tcb_info_str: Vec<u8> = tcb_info_str.iter().map(|&x| x as u8).collect();
        let tcb_info_str = std::str::from_utf8(&tcb_info_str)
            .unwrap()
            .trim_end_matches("\0");
        let enclave_identity_str = unsafe {
            std::slice::from_raw_parts(
                p_quote_collateral.as_ref().unwrap().qe_identity,
                p_quote_collateral.as_ref().unwrap().qe_identity_size as usize,
            )
        };
        let enclave_identity_str: Vec<u8> = enclave_identity_str.iter().map(|&x| x as u8).collect();
        let enclave_identity_str = std::str::from_utf8(&enclave_identity_str)
            .unwrap()
            .trim_end_matches("\0");
        let enclave_identity_issuer_chains_str = unsafe {
            std::slice::from_raw_parts(
                p_quote_collateral
                    .as_ref()
                    .unwrap()
                    .qe_identity_issuer_chain,
                p_quote_collateral
                    .as_ref()
                    .unwrap()
                    .qe_identity_issuer_chain_size as usize,
            )
        };
        let enclave_identity_issuer_chains_str: Vec<u8> = enclave_identity_issuer_chains_str
            .iter()
            .map(|&x| x as u8)
            .collect();
        let enclave_identity_issuer_chains_str =
            std::str::from_utf8(&enclave_identity_issuer_chains_str)
                .unwrap()
                .trim_end_matches("\0");
        println!("root_ca_crl: {}", root_ca_crl);
        println!("pck_crl: {}", pck_crl);
        println!("tcb_info_str: {:?}", tcb_info_str);
        println!("enclave_identity_str: {:?}", enclave_identity_str);
        println!(
            "enclave_identity_issuer_chains_str: {}",
            enclave_identity_issuer_chains_str
        );
        update_verification_collateral(
            provider,
            network,
            Some(root_ca_crl),
            pck_id,
            pck_crl,
            tcb_info_str,
            enclave_id,
            collateral_version.clone(),
            enclave_identity_str,
            enclave_identity_issuer_chains_str,
            all_verification_collateral,
            None,
        );

        let ret = azure::az_dcap_tdx_ql_free_quote_verification_collateral(p_quote_collateral);
        println!(
            "azure dcap tdx_ql_free_quote_verification_collateral func: {:?}",
            ret
        );
    }
    if data_source == DataSource::All || data_source == DataSource::Local {
        // Ref: https://download.01.org/intel-sgx/sgx-dcap/1.19/linux/docs/SGX_DCAP_Caching_Service_Design_Guide.pdf || 3.2 Section Get PCK Cert CRL
        let req_url = format!(
            "{}/sgx/certification/{}/pckcrl?ca={}",
            pccs_url,
            collateral_version.clone(),
            pck_ca.clone()
        );
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let response = match rt.block_on(reqwest::get(req_url.clone())) {
            Ok(v) => v,
            Err(_) => {
                println!("Unable to get {}", req_url);
                return;
            }
        };
        let pck_crl = if response.status().is_success() {
            let headers = response.headers();
            if let Some(cert) = headers.get("SGX-PCK-CRL-Issuer-Chain") {
                println!("SGX-PCK-CRL-Issuer-Chain: {:?}", cert);
            }
            let content = match rt.block_on(response.text()) {
                Ok(v) => v,
                Err(_) => {
                    println!("Unable to get the content of {}", req_url);
                    return;
                }
            };
            println!("SGX-PCK-CRL: {}", content);
            content
        } else {
            println!("[ERROR] {} returns {:?}, exit", req_url, response.status());
            #[allow(clippy::needless_return)]
            return;
        };
        // Ref: https://download.01.org/intel-sgx/sgx-dcap/1.19/linux/docs/SGX_DCAP_Caching_Service_Design_Guide.pdf || 3.7 Section Get Root CA CRL
        // This API endpoint is not found in Intel PCS: https://api.portal.trustedservices.intel.com/content/documentation.html
        // let req_url = format!(
        //     "{}/sgx/certification/{}/rootcacrl",
        //     pccs_url,
        //     collateral_version.clone()
        // );
        // let rt = tokio::runtime::Builder::new_current_thread()
        //     .enable_all()
        //     .build()
        //     .unwrap();
        // let response = match rt.block_on(reqwest::get(req_url.clone())) {
        //     Ok(v) => v,
        //     Err(_) => {
        //         println!("Unable to get {}", req_url);
        //         return;
        //     }
        // };
        // if response.status().is_success() {
        //     let content = match rt.block_on(response.text()) {
        //         Ok(v) => v,
        //         Err(_) => {
        //             println!("Unable to get the content of {}", req_url);
        //             return;
        //         }
        //     };
        //     println!("SGX-Root-CA-Crl: {:?}", content);
        // }
        // Ref: https://download.01.org/intel-sgx/sgx-dcap/1.19/linux/docs/SGX_DCAP_Caching_Service_Design_Guide.pdf || 3.3 Section Get TCB Info
        let req_url = format!(
            "{}/tdx/certification/{}/tcb?fmspc={}",
            pccs_url,
            collateral_version.clone(),
            fmspc
        );
        println!("req_url: {:?}", req_url);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let response = match rt.block_on(reqwest::get(req_url.clone())) {
            Ok(v) => v,
            Err(_) => {
                println!("Unable to get {}", req_url);
                return;
            }
        };
        let tcb_info_str = if response.status().is_success() {
            let headers = response.headers();
            // v3
            if let Some(cert) = headers.get("SGX-TCB-Info-Issuer-Chain") {
                println!("SGX-TCB-Info-Issuer-Chain: {:?}", cert);
            }
            // v4
            if let Some(cert) = headers.get("TCB-Info-Issuer-Chain") {
                println!("TCB-Info-Issuer-Chain: {:?}", cert);
            }
            let content = match rt.block_on(response.text()) {
                Ok(v) => v,
                Err(_) => {
                    println!("Unable to get the content of {}", req_url);
                    return;
                }
            };
            println!("TCB-Info: {}", content);
            content
        } else {
            println!("[ERROR] {} returns {:?}, exit", req_url, response.status());
            #[allow(clippy::needless_return)]
            return;
        };
        // Ref: https://download.01.org/intel-sgx/sgx-dcap/1.19/linux/docs/SGX_DCAP_Caching_Service_Design_Guide.pdf || 3.6 Section Get TD QE Identity
        let req_url = format!(
            "{}/tdx/certification/{}/qe/identity",
            pccs_url,
            collateral_version.clone()
        );
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let response = match rt.block_on(reqwest::get(req_url.clone())) {
            Ok(v) => v,
            Err(_) => {
                println!("Unable to get {}", req_url);
                return;
            }
        };
        if response.status().is_success() {
            let headers = response.headers();
            let enclave_identity_issuer_chains_str =
                if let Some(cert) = headers.get("SGX-Enclave-Identity-Issuer-Chain") {
                    cert.to_str().unwrap().to_string()
                } else {
                    println!(
                        "Cannot find SGX-Enclave-Identity-Issuer-Chain in {:?}, exit",
                        req_url
                    );
                    return;
                };
            let enclave_identity_issuer_chains_str =
                urlencoding::decode(&enclave_identity_issuer_chains_str).expect("Invalid UTF-8");
            let enclave_identity_issuer_chains_str = enclave_identity_issuer_chains_str.to_string();
            let qe_identity_str = match rt.block_on(response.text()) {
                Ok(v) => v,
                Err(_) => {
                    println!("Unable to get the content of {}", req_url);
                    return;
                }
            };
            println!(
                "SGX-Enclave-Identity-Issuer-Chain: {}",
                enclave_identity_issuer_chains_str
            );
            println!("TDX-QE-Identity: {}", qe_identity_str);
            update_verification_collateral(
                provider,
                network,
                None,
                pck_id,
                pck_crl.as_str(),
                tcb_info_str.as_str(),
                enclave_id,
                collateral_version.clone(),
                qe_identity_str.as_str(),
                enclave_identity_issuer_chains_str.as_str(),
                all_verification_collateral,
                None,
            );
        } else {
            println!("[ERROR] {} returns {:?}, exit", req_url, response.status());
            #[allow(clippy::needless_return)]
            return;
        };
    }
}

pub fn sgx_ql_get_qve_identity<P: Provider>(
    provider: &P,
    deployment_version: Option<Version>,
    data_source: DataSource,
    collateral_version: String,
    pccs_url: String,
) {
    // Derive network from provider
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let network = rt.block_on(async {
        Network::from_provider(provider, deployment_version).await
    }).expect("Failed to derive network from provider");

    let mut p_qve_identity: *mut c_char = std::ptr::null_mut();
    let pp_qve_identity: *mut *mut c_char = &mut p_qve_identity as *mut *mut c_char;
    let mut qve_identity_size: u32 = 0u32;
    let p_qve_identity_size: *mut u32 = &mut qve_identity_size;
    let mut p_qve_identity_issuer_chain: *mut c_char = std::ptr::null_mut();
    let pp_qve_identity_issuer_chain: *mut *mut c_char =
        &mut p_qve_identity_issuer_chain as *mut *mut c_char;
    let mut qve_identity_issuer_chain_size: u32 = 0u32;
    let p_qve_identity_issuer_chain_size: *mut u32 = &mut qve_identity_issuer_chain_size;

    if data_source == DataSource::All || data_source == DataSource::Azure {
        std::env::set_var("AZDCAP_COLLATERAL_VERSION", collateral_version.clone());
        let ret = azure::az_dcap_sgx_ql_get_qve_identity(
            pp_qve_identity,
            p_qve_identity_size,
            pp_qve_identity_issuer_chain,
            p_qve_identity_issuer_chain_size,
        );
        println!("azure dcap sgx_ql_get_qve_identity func: {:?}", ret);
        println!("qve_identity_size: {:?}", qve_identity_size);
        let qve_identity = unsafe { *pp_qve_identity };
        let qve_identity_c_str = unsafe {
            CStr::from_bytes_with_nul(std::slice::from_raw_parts(
                qve_identity as *const u8,
                qve_identity_size as usize,
            ))
        };
        let qve_identity_str = if let Ok(s) = qve_identity_c_str.map(|c| c.to_string_lossy()) {
            println!("qve_identity: {}", s);
            s.to_string()
        } else {
            println!("Unable to convert qve_identity");
            return;
        };

        println!(
            "qve_identity_issuer_chain_size: {:?}",
            qve_identity_issuer_chain_size
        );
        let qve_identity_issuer_chain = unsafe { *pp_qve_identity_issuer_chain };
        let qve_identity_issuer_chain_c_str = unsafe {
            CStr::from_bytes_with_nul(std::slice::from_raw_parts(
                qve_identity_issuer_chain as *const u8,
                qve_identity_issuer_chain_size as usize,
            ))
        };
        let issuer_chains_str =
            if let Ok(s) = qve_identity_issuer_chain_c_str.map(|c| c.to_string_lossy()) {
                println!("qve_identity_issuer_chain: {}", s);
                s.to_string()
            } else {
                println!("Unable to convert qve_identity_issuer_chain");
                return;
            };
        upsert_enclave_identity(
            provider,
            network,
            EnclaveID::QVE,
            collateral_version.clone(),
            &qve_identity_str,
            &issuer_chains_str,
            None,
        );

        let ret = azure::az_dcap_sgx_ql_free_qve_identity(qve_identity, qve_identity_issuer_chain);
        println!("azure dcap sgx_ql_free_qve_identity func: {:?}", ret);
    }
    if data_source == DataSource::All || data_source == DataSource::Local {
        // Ref: https://download.01.org/intel-sgx/sgx-dcap/1.19/linux/docs/SGX_DCAP_Caching_Service_Design_Guide.pdf || 3.5 Section Get QvE Identity
        let req_url = format!(
            "{}/sgx/certification/{}/qve/identity",
            pccs_url,
            collateral_version.clone()
        );
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let response = match rt.block_on(reqwest::get(req_url.clone())) {
            Ok(v) => v,
            Err(_) => {
                println!("Unable to get {}", req_url);
                return;
            }
        };
        if response.status().is_success() {
            let headers = response.headers();
            let issuer_chains_str =
                if let Some(cert) = headers.get("SGX-Enclave-Identity-Issuer-Chain") {
                    cert.to_str().unwrap().to_string()
                } else {
                    println!(
                        "Cannot find SGX-Enclave-Identity-Issuer-Chain in {:?}, exit",
                        req_url
                    );
                    return;
                };
            let issuer_chains_str = urlencoding::decode(&issuer_chains_str).expect("Invalid UTF-8");
            let issuer_chains_str = issuer_chains_str.to_string();
            let qve_identity_str = match rt.block_on(response.text()) {
                Ok(v) => v,
                Err(_) => {
                    println!("Unable to get the content of {}", req_url);
                    return;
                }
            };
            println!("SGX-Enclave-Identity-Issuer-Chain: {}", issuer_chains_str);
            println!("SGX-QvE-Identity: {}", qve_identity_str);

            upsert_enclave_identity(
                provider,
                network,
                EnclaveID::QVE,
                collateral_version.clone(),
                &qve_identity_str,
                &issuer_chains_str,
                None,
            );
        }
    }
}

pub fn sgx_ql_get_root_ca_crl<P: Provider>(
    provider: &P,
    deployment_version: Option<Version>,
    data_source: DataSource,
    collateral_version: String,
    pccs_url: String,
) {
    // Derive network from provider
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let network = rt.block_on(async {
        Network::from_provider(provider, deployment_version).await
    }).expect("Failed to derive network from provider");

    let mut p_root_ca_crl: *mut c_char = std::ptr::null_mut();
    let pp_root_ca_crl: *mut *mut c_char = &mut p_root_ca_crl as *mut *mut c_char;

    let mut root_ca_crl_size: u16 = 0;
    let p_root_ca_crl_size: *mut u16 = &mut root_ca_crl_size;

    if data_source == DataSource::All || data_source == DataSource::Azure {
        std::env::set_var("AZDCAP_COLLATERAL_VERSION", collateral_version.clone());
        let ret = azure::az_dcap_sgx_ql_get_root_ca_crl(pp_root_ca_crl, p_root_ca_crl_size);
        println!("azure dcap sgx_ql_get_root_ca_crl func: {:?}", ret);
        println!("root_ca_crl_size: {:?}", root_ca_crl_size);
        let root_ca_crl = unsafe { *pp_root_ca_crl };
        let root_ca_crl_c_str = unsafe {
            CStr::from_bytes_with_nul(std::slice::from_raw_parts(
                root_ca_crl as *const u8,
                root_ca_crl_size as usize,
            ))
        };

        let crl = if let Ok(s) = root_ca_crl_c_str.map(|c| c.to_string_lossy()) {
            println!("root_ca_crl: {}", s);
            s.to_string()
        } else {
            println!("Unable to convert root_ca_crl");
            return;
        };
        upsert_root_ca_crl(provider, network, &crl);

        let ret = azure::az_dcap_sgx_ql_free_root_ca_crl(root_ca_crl);
        println!("azure dcap sgx_ql_free_root_ca_crl func: {:?}", ret);
    }
    if data_source == DataSource::All || data_source == DataSource::Local {
        // Ref: https://download.01.org/intel-sgx/sgx-dcap/1.19/linux/docs/SGX_DCAP_Caching_Service_Design_Guide.pdf || 3.7 Section Get Root CA CRL
        let req_url = format!(
            "{}/sgx/certification/{}/rootcacrl",
            pccs_url,
            collateral_version.clone()
        );
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let response = match rt.block_on(reqwest::get(req_url.clone())) {
            Ok(v) => v,
            Err(_) => {
                println!("Unable to get {}", req_url);
                return;
            }
        };
        if response.status().is_success() {
            let content = match rt.block_on(response.text()) {
                Ok(v) => v,
                Err(_) => {
                    println!("Unable to get the content of {}", req_url);
                    return;
                }
            };
            println!("SGX-Root-CA-Crl: {:?}", content);
        }
    }
}
