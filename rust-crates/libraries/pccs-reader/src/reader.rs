use alloy::providers::Provider;
use anyhow::Result;
use automata_dcap_network_registry::Network;
use automata_dcap_utils::Version;

use crate::pccs::enclave_id::{get_enclave_identity_at_address, EnclaveIdType};
use crate::pccs::fmspc_tcb::get_tcb_info_at_address;
use crate::pccs::pcs::{get_certificate_by_id_at_address, CA};
use crate::{CollateralError, Collaterals};

/// Reusable reader for Automata on-chain PCCS collateral.
///
/// A reader keeps the caller's provider and one resolved [`Network`]. Reusing
/// it avoids repeating `eth_chainId` before every collateral read.
pub struct PccsReader<'a, P: Provider> {
    provider: &'a P,
    network: Network,
}

impl<'a, P: Provider> PccsReader<'a, P> {
    /// Creates a reader by selecting a registered network from the provider's
    /// chain ID.
    ///
    /// This constructor performs one `eth_chainId` request.
    pub async fn from_provider(
        provider: &'a P,
        deployment_version: Option<Version>,
    ) -> Result<Self> {
        let network = Network::from_provider(provider, deployment_version)
            .await?
            .clone();
        Ok(Self { provider, network })
    }

    /// Creates a reader from a network that the caller already selected.
    ///
    /// This constructor does not query the provider's chain ID. The caller must
    /// ensure that `provider` and `network` refer to the same chain.
    pub fn from_network(provider: &'a P, network: &Network) -> Self {
        Self {
            provider,
            network: network.clone(),
        }
    }

    /// Returns the network used to resolve PCCS contract addresses.
    pub fn network(&self) -> &Network {
        &self.network
    }

    pub(crate) fn provider(&self) -> &P {
        self.provider
    }

    /// Reads one certificate and certificate revocation list from `PcsDao`.
    pub async fn get_certificate_by_id(&self, ca_id: CA) -> Result<(Vec<u8>, Vec<u8>)> {
        get_certificate_by_id_at_address(self.provider, self.network.contracts.pccs.pcs_dao, ca_id)
            .await
    }

    /// Reads one enclave identity from the DAO selected by the TCB evaluation
    /// data number.
    pub async fn get_enclave_identity(
        &self,
        id: EnclaveIdType,
        version: u32,
        tcb_eval_num: Option<u32>,
    ) -> Result<Vec<u8>> {
        let tcb_id = match id {
            EnclaveIdType::TDQE => 1,
            EnclaveIdType::QE | EnclaveIdType::QVE => 0,
        };
        let evaluation_data_number = self
            .network
            .resolve_tcb_evaluation_data_number(self.provider, tcb_eval_num, tcb_id)
            .await?;
        let dao_address = self
            .network
            .contracts
            .pccs
            .enclave_id_dao
            .get_address(evaluation_data_number)?;

        get_enclave_identity_at_address(self.provider, dao_address, id, version).await
    }

    /// Reads FMSPC TCB information from the DAO selected by the TCB evaluation
    /// data number.
    pub async fn get_tcb_info(
        &self,
        tcb_type: u8,
        fmspc: &str,
        version: u32,
        tcb_eval_num: Option<u32>,
    ) -> Result<Vec<u8>> {
        let evaluation_data_number = self
            .network
            .resolve_tcb_evaluation_data_number(self.provider, tcb_eval_num, tcb_type)
            .await?;
        let dao_address = self
            .network
            .contracts
            .pccs
            .fmspc_tcb_dao
            .get_address(evaluation_data_number)?;

        get_tcb_info_at_address(self.provider, dao_address, tcb_type, fmspc, version).await
    }

    /// Finds missing or outdated collateral for an SGX or TDX quote.
    ///
    /// The TCB evaluation data number is resolved once per call. Independent
    /// contract reads run concurrently.
    pub async fn find_missing_collaterals_from_quote(
        &self,
        raw_quote: &[u8],
        print: bool,
        tcb_eval_num: Option<u32>,
    ) -> Result<Collaterals, CollateralError> {
        crate::find_missing_collaterals_with_reader(self, raw_quote, print, tcb_eval_num).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::U64;
    use alloy::providers::ProviderBuilder;
    use alloy::transports::mock::Asserter;

    #[tokio::test]
    async fn from_provider_reads_chain_id_once() {
        let network = Network::default_network(None).unwrap();
        let asserter = Asserter::new();
        asserter.push_success(&U64::from(network.chain_id));
        let provider = ProviderBuilder::new().connect_mocked_client(asserter.clone());

        let reader = PccsReader::from_provider(&provider, None).await.unwrap();

        assert_eq!(reader.network().chain_id, network.chain_id);
        assert!(asserter.read_q().is_empty());
    }

    #[test]
    fn from_network_does_not_read_chain_id() {
        let network = Network::default_network(None).unwrap();
        let asserter = Asserter::new();
        let provider = ProviderBuilder::new().connect_mocked_client(asserter.clone());

        let reader = PccsReader::from_network(&provider, network);

        assert_eq!(reader.network().chain_id, network.chain_id);
        assert!(asserter.read_q().is_empty());
    }
}
