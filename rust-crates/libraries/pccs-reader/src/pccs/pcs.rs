use alloy::providers::Provider;
use anyhow::Result;
use automata_dcap_evm_bindings::r#i_pcs_dao::IPcsDao;
use automata_dcap_network_registry::Network;
use automata_dcap_utils::Version;

/// Certificate authority identifiers used by the PCCS DAO.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CA {
    Root = 0,
    Processor = 1,
    Platform = 2,
    Signing = 3,
}

impl CA {
    pub const ROOT: CA = CA::Root;
    pub const PROCESSOR: CA = CA::Processor;
    pub const PLATFORM: CA = CA::Platform;
    pub const SIGNING: CA = CA::Signing;

    fn as_u8(self) -> u8 {
        self as u8
    }
}

pub async fn get_certificate_by_id<P: Provider>(
    provider: &P,
    deployment_version: Option<Version>,
    ca_id: CA,
) -> Result<(Vec<u8>, Vec<u8>)> {
    // Derive network from provider to get contract address
    let network = Network::from_provider(provider, deployment_version).await?;

    let contract = IPcsDao::new(network.contracts.pccs.pcs_dao, provider);

    let response = contract
        .getCertificateById(ca_id.as_u8())
        .from(alloy::primitives::Address::ZERO)
        .call()
        .await?;

    let cert = response.cert.to_vec();
    let crl = response.crl.to_vec();

    Ok((cert, crl))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::sol_types::SolCall;
    use automata_dcap_evm_bindings::r#i_pcs_dao::IPcsDao::getCertificateByIdCall;
    use automata_dcap_network_registry::Network;

    #[test]
    fn pcs_get_certificate_call_has_expected_selector() {
        let call = getCertificateByIdCall {
            ca: CA::Root.as_u8(),
        };
        let encoded = call.abi_encode();
        assert_eq!(&encoded[..4], &getCertificateByIdCall::SELECTOR);
        assert_eq!(encoded.len(), 4 + 32);
    }

    #[tokio::test]
    async fn pcs_contract_uses_registry_address() {
        use alloy::providers::ProviderBuilder;

        let network = Network::default_network(None).unwrap();
        let call = getCertificateByIdCall {
            ca: CA::Root.as_u8(),
        };
        let encoded = call.abi_encode();
        // Smoke-check that we can instantiate the contract with the registry address.
        let provider =
            ProviderBuilder::new().connect_http(network.default_rpc_url().parse().unwrap());
        let contract =
            IPcsDao::new(network.contracts.pccs.pcs_dao, provider);
        let _ = (encoded, contract);
    }
}
