use alloy::primitives::U256;
use alloy::providers::Provider;
use anyhow::Result;
use automata_dcap_evm_bindings::r#i_fmspc_tcb_dao::IFmspcTcbDao;
use automata_dcap_network_registry::{ContractKind, Network};
use automata_dcap_utils::Version;

pub async fn get_tcb_info<P: Provider>(
    provider: &P,
    deployment_version: Option<Version>,
    tcb_type: u8,
    fmspc: &str,
    version: u32,
    tcb_eval_num: Option<u32>,
) -> Result<Vec<u8>> {
    // Derive network from provider for contract resolution
    let network = Network::from_provider(provider, deployment_version).await?;

    // Resolve contract address - will call standard() if tcb_eval_num is None
    let dao_address = network
        .resolve_contract_address(ContractKind::FmspcTcbDao, tcb_eval_num, Some(tcb_type))
        .await?;

    let fmspc_tcb_dao_contract = IFmspcTcbDao::new(dao_address, provider);

    let call_return = fmspc_tcb_dao_contract
        .getTcbInfo(
            U256::from(tcb_type),
            String::from(fmspc),
            U256::from(version),
        )
        .from(alloy::primitives::Address::ZERO)
        .call()
        .await?;
    let tcb_info_str = call_return.tcbInfoStr;
    let signature_bytes = call_return.signature;

    if tcb_info_str.is_empty() || signature_bytes.is_empty() {
        return Err(anyhow::Error::msg("missing"));
    }

    let signature = signature_bytes.to_string();

    let ret_str = format!(
        "{{\"tcbInfo\": {}, \"signature\": \"{}\"}}",
        tcb_info_str,
        remove_prefix_if_found(signature.as_str())
    );

    let ret = ret_str.into_bytes();
    Ok(ret)
}

fn remove_prefix_if_found(h: &str) -> &str {
    h.strip_prefix("0x").unwrap_or(h)
}
