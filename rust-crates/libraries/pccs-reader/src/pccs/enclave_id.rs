use alloy::primitives::U256;
use alloy::providers::Provider;
use anyhow::Result;
use automata_dcap_evm_bindings::r#i_enclave_identity_dao::IEnclaveIdentityDao;
use automata_dcap_network_registry::{ContractKind, Network};
use automata_dcap_utils::Version;

#[derive(Debug, Clone, Copy)]
pub enum EnclaveIdType {
    QE,
    QVE,
    TDQE,
}

pub async fn get_enclave_identity<P: Provider>(
    provider: &P,
    deployment_version: Option<Version>,
    id: EnclaveIdType,
    version: u32,
    tcb_eval_num: Option<u32>,
) -> Result<Vec<u8>> {
    // Derive network from provider for contract resolution
    let network = Network::from_provider(provider, deployment_version).await?;

    // Determine TcbId based on enclave type
    let tcb_id = match id {
        EnclaveIdType::TDQE => 1, // TDX
        EnclaveIdType::QE | EnclaveIdType::QVE => 0, // SGX
    };

    // Resolve contract address - will call standard() if tcb_eval_num is None
    let dao_address = network
        .resolve_contract_address(ContractKind::EnclaveIdDao, tcb_eval_num, Some(tcb_id))
        .await?;

    let enclave_id_dao_contract = IEnclaveIdentityDao::new(dao_address, provider);

    let enclave_id_type_uint256 = match id {
        EnclaveIdType::QE => U256::from(0),
        EnclaveIdType::QVE => U256::from(1),
        EnclaveIdType::TDQE => U256::from(2),
    };

    let call_return = enclave_id_dao_contract
        .getEnclaveIdentity(enclave_id_type_uint256, U256::from(version))
        .from(alloy::primitives::Address::ZERO)
        .call()
        .await?;

    let identity_str = call_return.identityStr;
    let signature_bytes = call_return.signature;

    if identity_str.is_empty() || signature_bytes.is_empty() {
        return Err(anyhow::Error::msg("missing"));
    }

    let signature = signature_bytes.to_string();

    let ret_str = format!(
        "{{\"enclaveIdentity\": {}, \"signature\": \"{}\"}}",
        identity_str,
        remove_prefix_if_found(signature.as_str())
    );

    let ret = ret_str.into_bytes();
    Ok(ret)
}

fn remove_prefix_if_found(h: &str) -> &str {
    h.strip_prefix("0x").unwrap_or(h)
}
