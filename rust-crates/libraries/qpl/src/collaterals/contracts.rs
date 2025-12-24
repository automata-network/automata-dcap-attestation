use super::pccs_types::*;
use alloy::primitives::{Bytes, U256};
use alloy::providers::Provider;
use automata_dcap_evm_bindings::r#i_enclave_identity_dao::IEnclaveIdentityDao;
use automata_dcap_evm_bindings::r#i_enclave_identity_dao::IEnclaveIdentityDao::EnclaveIdentityJsonObj;
use automata_dcap_evm_bindings::r#i_fmspc_tcb_dao::IFmspcTcbDao;
use automata_dcap_evm_bindings::r#i_fmspc_tcb_dao::IFmspcTcbDao::TcbInfoJsonObj;
use automata_dcap_evm_bindings::r#i_pck_dao::IPckDao;
use automata_dcap_evm_bindings::r#i_pcs_dao::IPcsDao;
use automata_dcap_network_registry::{ContractKind, Network};
use crate::types::*;
use openssl::x509::{X509, X509Crl};

fn get_gas_price(network: &Network) -> u128 {
    network.gas_price_hint_wei().unwrap_or(10000u128)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn upsert_pck_cert<P: Provider>(
    provider: &P,
    network: &Network,
    ca: CAID,
    qe_id: String,
    pce_id: String,
    cpu_svn: String,
    pce_svn: String,
    tcbm: String,
    cert_chains_str: &str,
) {

    let pck_dao = IPckDao::new(network.contracts.pccs.pck_dao, &provider);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let certs_str: Vec<&str> = cert_chains_str.split("-----END CERTIFICATE-----").collect();
    let mut certs = Vec::new();
    for cert in certs_str {
        let current_cert = cert.trim();
        if current_cert == "\0" {
            continue;
        }
        if !current_cert.is_empty() {
            let cert_str: String = format!("{}\n-----END CERTIFICATE-----\n", current_cert);
            match X509::from_pem(cert_str.as_bytes()) {
                Ok(cert) => {
                    certs.push(hex::encode(cert.to_der().unwrap()));
                }
                Err(err) => {
                    println!("Error parsing certificate: {:?}", err);
                    return;
                }
            }
        }
    }
    assert_eq!(certs.len(), 3);

    let pcs_dao = IPcsDao::new(network.contracts.pccs.pcs_dao, &provider);

    // TODO: Check the Root and Platform/Process intermediate certs before upsert
    let cert_bytes = Bytes::from(hex::decode(&certs[2]).unwrap());
    match rt.block_on(
        pcs_dao
            .upsertPcsCertificates(CAID::Root as u8, cert_bytes)
            .gas_price(get_gas_price(network))
            .send(),
    ) {
        Ok(pending_tx) => {
            let tx_hash = *pending_tx.tx_hash();
            println!("txn[upsert_pcs_certificates][root] hash: {:?}", tx_hash);
            match rt.block_on(pending_tx.watch()) {
                Ok(receipt) => {
                    println!("txn[upsert_pcs_certificates][root] receipt: {:?}", receipt);
                }
                Err(err) => {
                    println!(
                        "txn[upsert_pcs_certificates][root] receipt meet error: {:?}",
                        err
                    );
                }
            }
        }
        Err(err) => {
            println!("txn[upsert_pcs_certificates][root] meet error: {:?}", err);
        }
    }
    let cert_bytes = Bytes::from(hex::decode(&certs[1]).unwrap());
    match rt.block_on(
        pcs_dao
            .upsertPcsCertificates(ca as u8, cert_bytes)
            .gas_price(get_gas_price(network))
            .send(),
    ) {
        Ok(pending_tx) => {
            let tx_hash = *pending_tx.tx_hash();
            println!("txn[upsert_pcs_certificates][intermediate] hash: {:?}", tx_hash);
            match rt.block_on(pending_tx.watch()) {
                Ok(receipt) => {
                    println!(
                        "txn[upsert_pcs_certificates][intermediate] receipt: {:?}",
                        receipt
                    );
                }
                Err(err) => {
                    println!(
                        "txn[upsert_pcs_certificates][intermediate] receipt meet error: {:?}",
                        err
                    );
                }
            }
        }
        Err(err) => {
            println!(
                "txn[upsert_pcs_certificates][intermediate] meet error: {:?}",
                err
            );
        }
    }
    let cert_bytes = Bytes::from(hex::decode(&certs[0]).unwrap());
    match rt.block_on(
        pck_dao
            .upsertPckCert(
                ca as u8,
                qe_id.clone(),
                pce_id.clone(),
                tcbm.clone(),
                cert_bytes,
            )
            .gas_price(get_gas_price(network))
            .send(),
    ) {
        Ok(pending_tx) => {
            let tx_hash = *pending_tx.tx_hash();
            println!("txn[upsert_pck_cert] hash: {:?}", tx_hash);
            match rt.block_on(pending_tx.watch()) {
                Ok(receipt) => {
                    println!("txn[upsert_pck_cert] receipt: {:?}", receipt);
                }
                Err(err) => {
                    println!("txn[upsert_pck_cert] receipt meet error: {:?}", err);
                }
            }
        }
        Err(err) => {
            println!("txn[upsert_pck_cert] meet error: {:?}", err);
        }
    };
    match rt.block_on(
        pck_dao
            .upsertPlatformTcbs(qe_id, pce_id, cpu_svn, pce_svn, tcbm)
            .gas_price(get_gas_price(network))
            .send(),
    ) {
        Ok(pending_tx) => {
            let tx_hash = *pending_tx.tx_hash();
            println!("txn[upsert_platform_tcbs] hash: {:?}", tx_hash);
            match rt.block_on(pending_tx.watch()) {
                Ok(receipt) => {
                    println!("txn[upsert_platform_tcbs] receipt: {:?}", receipt);
                }
                Err(err) => {
                    println!("txn[upsert_platform_tcbs] receipt meet error: {:?}", err);
                }
            }
        }
        Err(err) => {
            println!("txn[upsert_platform_tcbs] meet error: {:?}", err);
        }
    };
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn upsert_enclave_identity<P: Provider>(
    provider: &P,
    network: &Network,
    enclave_id: EnclaveID,
    collateral_version: String,
    enclave_identity_str: &str,
    enclave_identity_issuer_chains_str: &str,
    tcb_eval_num: Option<u32>,
) {

    let pcs_dao = IPcsDao::new(network.contracts.pccs.pcs_dao, &provider);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    // Determine tcb_id based on enclave type
    let tcb_id = match enclave_id {
        EnclaveID::TD_QE => 1, // TDX
        EnclaveID::QE | EnclaveID::QVE => 0, // SGX
    };

    let enclave_id_dao_address = rt.block_on(async {
        network.resolve_contract_address(ContractKind::EnclaveIdDao, tcb_eval_num, Some(tcb_id)).await
    }).unwrap();
    let enclave_identity_dao = IEnclaveIdentityDao::new(enclave_id_dao_address, &provider);
    let certs_str: Vec<&str> = enclave_identity_issuer_chains_str
        .split("-----END CERTIFICATE-----")
        .collect();
    let mut certs = Vec::new();
    for cert in certs_str {
        let current_cert = cert.trim();
        if current_cert == "\0" {
            continue;
        }
        if !current_cert.is_empty() {
            let cert_str = format!("{}\n-----END CERTIFICATE-----\n", current_cert);
            match X509::from_pem(cert_str.as_bytes()) {
                Ok(cert) => {
                    certs.push(hex::encode(cert.to_der().unwrap()));
                }
                Err(err) => {
                    println!("Error parsing certificate: {:?}", err);
                    return;
                }
            }
        }
    }
    assert_eq!(certs.len(), 2);
    // TODO: Check the Root and Signing certs before upsert
    #[allow(clippy::single_match)]
    let cert_bytes = Bytes::from(hex::decode(&certs[1]).unwrap());
    match rt.block_on(
        pcs_dao
            .upsertPcsCertificates(CAID::Root as u8, cert_bytes)
            .gas_price(get_gas_price(network))
            .send(),
    ) {
        Ok(pending_tx) => {
            let tx_hash = *pending_tx.tx_hash();
            println!("txn[upsert_pcs_certificates][root] hash: {:?}", tx_hash);
            #[allow(clippy::single_match)]
            match rt.block_on(pending_tx.watch()) {
                Ok(receipt) => {
                    println!("txn[upsert_pcs_certificates][root] receipt: {:?}", receipt);
                }
                Err(_) => {}
            }
        }
        Err(_) => {}
    }
    let cert_bytes = Bytes::from(hex::decode(&certs[0]).unwrap());
    match rt.block_on(
        pcs_dao
            .upsertPcsCertificates(CAID::Signing as u8, cert_bytes)
            .gas_price(get_gas_price(network))
            .send(),
    ) {
        Ok(pending_tx) => {
            let tx_hash = *pending_tx.tx_hash();
            println!("txn[upsert_pcs_certificates][signing] hash: {:?}", tx_hash);
            match rt.block_on(pending_tx.watch()) {
                Ok(receipt) => {
                    println!(
                        "txn[upsert_pcs_certificates][signing] receipt: {:?}",
                        receipt
                    );
                }
                Err(err) => {
                    println!("Error: {:?}", err);
                }
            }
        }
        Err(err) => {
            println!("Error: {:?}", err);
        }
    }

    let enclave_identity: EnclaveIdentity = serde_json::from_str(enclave_identity_str).unwrap();
    // Jiaquan: we cannot use serde lib to deserialize the enclave_identity_str, because in v4 struct, an inner struct is also indexmap here
    // Need to have a better implementation here
    let enclave_identity_str = &enclave_identity_str[r#""enclaveIdentity":{"#.len()..];
    let end_idx = enclave_identity_str.find(r#","signature""#).unwrap();
    let enclave_identity_str = &enclave_identity_str[..end_idx];
    let signature_bytes: Bytes = enclave_identity.signature.parse().unwrap();
    let enclave_identity_obj = EnclaveIdentityJsonObj {
        identityStr: enclave_identity_str.to_string(),
        signature: signature_bytes,
    };
    println!("identity_str = {}", enclave_identity_obj.identityStr);
    println!("signature = {}", enclave_identity_obj.signature);
    // println!("{:?}", enclave_identity_dao.upsertEnclaveIdentity(id, version, enclave_identity_obj));
    match rt.block_on(
        enclave_identity_dao
            .upsertEnclaveIdentity(id, version, enclave_identity_obj)
            .gas_price(get_gas_price(network))
            .send(),
    ) {
        Ok(pending_tx) => {
            let tx_hash = *pending_tx.tx_hash();
            println!("txn[upsert_enclave_identity] hash: {:?}", tx_hash);
            match rt.block_on(pending_tx.watch()) {
                Ok(receipt) => {
                    println!("txn[upsert_enclave_identity] receipt: {:?}", receipt);
                }
                Err(err) => {
                    println!("txn[upsert_enclave_identity] receipt meet error: {:?}", err);
                }
            }
        }
        Err(err) => {
            println!("txn[upsert_enclave_identity] meet error: {:?}", err);
        }
    };
}

pub(crate) fn upsert_root_ca_crl<P: Provider>(
    provider: &P,
    network: &Network,
    crl: &str,
) {

    let pcs_dao = IPcsDao::new(network.contracts.pccs.pcs_dao, &provider);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let crl = match X509Crl::from_pem(crl.as_bytes()) {
        Ok(c) => hex::encode(c.to_der().unwrap()),
        Err(err) => {
            println!("Error parsing certificate: {:?}", err);
            return;
        }
    };
    let crl_bytes = Bytes::from(hex::decode(&crl).unwrap());
    match rt.block_on(
        pcs_dao
            .upsertRootCACrl(crl_bytes)
            .gas_price(get_gas_price(network))
            .send(),
    ) {
        Ok(pending_tx) => {
            let tx_hash = *pending_tx.tx_hash();
            println!("txn[upsert_root_ca_crl] hash: {:?}", tx_hash);
            match rt.block_on(pending_tx.watch()) {
                Ok(receipt) => {
                    println!("txn[upsert_root_ca_crl] receipt: {:?}", receipt);
                }
                Err(err) => {
                    println!("txn[upsert_root_ca_crl] receipt meet error: {:?}", err);
                }
            }
        }
        Err(err) => {
            println!("txn[upsert_root_ca_crl] meet error: {:?}", err);
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn update_verification_collateral<P: Provider>(
    provider: &P,
    network: &Network,
    root_ca_crl: Option<&str>,
    pck: CAID,
    pck_crl: &str,
    tcb_info_str: &str,
    enclave_id: EnclaveID,
    collateral_version: String,
    enclave_identity_str: &str,
    enclave_identity_issuer_chains_str: &str,
    all_verification_collateral: u64,
    tcb_eval_num: Option<u32>,
) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let pcs_dao = IPcsDao::new(network.contracts.pccs.pcs_dao, &provider);

    // Determine tcb_id based on enclave type
    let tcb_id = match enclave_id {
        EnclaveID::TD_QE => 1, // TDX
        EnclaveID::QE | EnclaveID::QVE => 0, // SGX
    };

    let fmspc_tcb_dao_address = rt.block_on(async {
        network.resolve_contract_address(ContractKind::FmspcTcbDao, tcb_eval_num, Some(tcb_id)).await
    }).unwrap();
    let fmspc_tcb_dao = IFmspcTcbDao::new(fmspc_tcb_dao_address, &provider);

    // Root CA CRL
    if all_verification_collateral == 1 {
        if let Some(root_ca_crl) = root_ca_crl {
            upsert_root_ca_crl(provider, network, root_ca_crl);
        }
    }

    // PCK CRL
    if all_verification_collateral == 1 {
        let pck_crl = match X509Crl::from_pem(pck_crl.as_bytes()) {
            Ok(c) => hex::encode(c.to_der().unwrap()),
            Err(err) => {
                println!("Error parsing certificate: {:?}", err);
                return;
            }
        };
        let pck_crl_bytes = Bytes::from(hex::decode(&pck_crl).unwrap());
        println!("[Jiaquan] pck: {:?}", pck as u8);
        println!("[Jiaquan] pck_crl: {:?}", pck_crl_bytes);
        match rt.block_on(
            pcs_dao
                .upsertPckCrl(pck as u8, pck_crl_bytes)
                .gas_price(get_gas_price(network))
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

    // TCB Info
    let tcb_info: TcbInfo = serde_json::from_str(tcb_info_str).unwrap();
    // Jiaquan: we cannot use serde lib to deserialize the tcb_info_str, because tcbLevels inner struct also need to be indexmap here
    // Need to have a better implementation here
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
    match rt.block_on(
        fmspc_tcb_dao
            .upsertFmspcTcb(tcb_info_obj)
            .gas_price(get_gas_price(network))
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

    // QE/TDX Identity
    if all_verification_collateral == 1 {
        upsert_enclave_identity(
            provider,
            network,
            enclave_id,
            collateral_version,
            enclave_identity_str,
            enclave_identity_issuer_chains_str,
            tcb_eval_num,
        );
    }
}
