use alloy::primitives::{Address, U256};
use alloy::providers::Provider;
use automata_dcap_evm_bindings::r#i_enclave_identity_dao::IEnclaveIdentityDao;
use automata_dcap_evm_bindings::r#i_fmspc_tcb_dao::IFmspcTcbDao;
use automata_dcap_evm_bindings::r#i_pcs_dao::IPcsDao;
use automata_dcap_evm_bindings::r#i_tcb_eval_dao::ITcbEvalDao;

use crate::pccs::enclave_id::{
    enclave_identity_from_return, get_enclave_identity_at_address, EnclaveIdType,
};
use crate::pccs::fmspc_tcb::{get_tcb_info_at_address, tcb_info_from_return};
use crate::pccs::pcs::{certificate_from_return, get_certificate_by_id_at_address, CA};
use crate::{
    read_collateral_results_direct, CollateralReadResults, PccsReader, QuoteCollateralRequirements,
    PCS_API_VERSION, TCB_VERSION,
};

pub(crate) async fn read_collateral_results<P: Provider>(
    reader: &PccsReader<'_, P>,
    requirements: &QuoteCollateralRequirements,
    tcb_eval_num: Option<u32>,
    multicall_address: Address,
) -> CollateralReadResults {
    if reader.network().version.uses_versioned_daos() && tcb_eval_num.is_none() {
        read_with_standard_lookup(reader, requirements, multicall_address).await
    } else {
        let evaluation_data_number = match reader
            .network()
            .resolve_tcb_evaluation_data_number(
                reader.provider(),
                tcb_eval_num,
                requirements.tcb_type,
            )
            .await
        {
            Ok(number) => number,
            Err(_) => {
                return read_collateral_results_direct(reader, requirements, tcb_eval_num).await;
            }
        };

        read_single_batch(
            reader,
            requirements,
            evaluation_data_number,
            tcb_eval_num,
            multicall_address,
        )
        .await
    }
}

async fn read_single_batch<P: Provider>(
    reader: &PccsReader<'_, P>,
    requirements: &QuoteCollateralRequirements,
    evaluation_data_number: u32,
    tcb_eval_num: Option<u32>,
    multicall_address: Address,
) -> CollateralReadResults {
    let provider = reader.provider();
    let network = reader.network();
    let qe_dao_address = match network
        .contracts
        .pccs
        .enclave_id_dao
        .get_address(evaluation_data_number)
    {
        Ok(address) => address,
        Err(_) => {
            return read_collateral_results_direct(reader, requirements, tcb_eval_num).await;
        }
    };
    let tcb_dao_address = match network
        .contracts
        .pccs
        .fmspc_tcb_dao
        .get_address(evaluation_data_number)
    {
        Ok(address) => address,
        Err(_) => {
            return read_collateral_results_direct(reader, requirements, tcb_eval_num).await;
        }
    };

    let pcs_dao = IPcsDao::new(network.contracts.pccs.pcs_dao, provider);
    let enclave_id_dao = IEnclaveIdentityDao::new(qe_dao_address, provider);
    let fmspc_tcb_dao = IFmspcTcbDao::new(tcb_dao_address, provider);
    let batch = provider
        .multicall()
        .address(multicall_address)
        .add(pcs_dao.getCertificateById(CA::ROOT.as_u8()))
        .add(pcs_dao.getCertificateById(CA::SIGNING.as_u8()))
        .add(pcs_dao.getCertificateById(requirements.pck_type.as_u8()))
        .add(enclave_id_dao.getEnclaveIdentity(
            U256::from(enclave_id_number(requirements.qe_id_type)),
            U256::from(PCS_API_VERSION),
        ))
        .add(fmspc_tcb_dao.getTcbInfo(
            U256::from(requirements.tcb_type),
            requirements.fmspc.clone(),
            U256::from(TCB_VERSION),
        ));

    let (root, signing, pck, qe, tcb) = match batch.try_aggregate(false).await {
        Ok(results) => results,
        Err(_) => {
            return read_collateral_results_direct(reader, requirements, tcb_eval_num).await;
        }
    };

    let root_read = retry_certificate(root, provider, network.contracts.pccs.pcs_dao, CA::ROOT);
    let signing_read = retry_certificate(
        signing,
        provider,
        network.contracts.pccs.pcs_dao,
        CA::SIGNING,
    );
    let pck_read = retry_certificate(
        pck,
        provider,
        network.contracts.pccs.pcs_dao,
        requirements.pck_type,
    );
    let qe_read = retry_enclave_identity(qe, provider, qe_dao_address, requirements.qe_id_type);
    let tcb_read = retry_tcb_info(
        tcb,
        provider,
        tcb_dao_address,
        requirements.tcb_type,
        requirements.fmspc.as_str(),
    );
    let (root, signing, pck, qe, tcb) =
        tokio::join!(root_read, signing_read, pck_read, qe_read, tcb_read);

    CollateralReadResults {
        root,
        signing,
        pck,
        qe,
        tcb,
    }
}

async fn read_with_standard_lookup<P: Provider>(
    reader: &PccsReader<'_, P>,
    requirements: &QuoteCollateralRequirements,
    multicall_address: Address,
) -> CollateralReadResults {
    let provider = reader.provider();
    let network = reader.network();
    let pcs_dao = IPcsDao::new(network.contracts.pccs.pcs_dao, provider);
    let tcb_eval_dao = ITcbEvalDao::new(network.contracts.pccs.tcb_eval_dao, provider);
    let first_batch = provider
        .multicall()
        .address(multicall_address)
        .add(pcs_dao.getCertificateById(CA::ROOT.as_u8()))
        .add(pcs_dao.getCertificateById(CA::SIGNING.as_u8()))
        .add(pcs_dao.getCertificateById(requirements.pck_type.as_u8()))
        .add(tcb_eval_dao.standard(requirements.tcb_type));

    let (root, signing, pck, evaluation_data_number) = match first_batch.try_aggregate(false).await
    {
        Ok(results) => results,
        Err(_) => {
            return read_collateral_results_direct(reader, requirements, None).await;
        }
    };

    let root_read = retry_certificate(root, provider, network.contracts.pccs.pcs_dao, CA::ROOT);
    let signing_read = retry_certificate(
        signing,
        provider,
        network.contracts.pccs.pcs_dao,
        CA::SIGNING,
    );
    let pck_read = retry_certificate(
        pck,
        provider,
        network.contracts.pccs.pcs_dao,
        requirements.pck_type,
    );
    let evaluation_data_number_read = async {
        match evaluation_data_number {
            Ok(number) => Ok(number),
            Err(_) => {
                network
                    .resolve_tcb_evaluation_data_number(provider, None, requirements.tcb_type)
                    .await
            }
        }
    };
    let (root, signing, pck, evaluation_data_number) = tokio::join!(
        root_read,
        signing_read,
        pck_read,
        evaluation_data_number_read
    );

    let evaluation_data_number = match evaluation_data_number {
        Ok(number) => number,
        Err(error) => {
            let (qe, tcb) = versioned_lookup_errors(error);
            return CollateralReadResults {
                root,
                signing,
                pck,
                qe,
                tcb,
            };
        }
    };
    let qe_dao_address = match network
        .contracts
        .pccs
        .enclave_id_dao
        .get_address(evaluation_data_number)
    {
        Ok(address) => address,
        Err(error) => {
            let (qe, tcb) = versioned_lookup_errors(error);
            return CollateralReadResults {
                root,
                signing,
                pck,
                qe,
                tcb,
            };
        }
    };
    let tcb_dao_address = match network
        .contracts
        .pccs
        .fmspc_tcb_dao
        .get_address(evaluation_data_number)
    {
        Ok(address) => address,
        Err(error) => {
            let (qe, tcb) = versioned_lookup_errors(error);
            return CollateralReadResults {
                root,
                signing,
                pck,
                qe,
                tcb,
            };
        }
    };

    let enclave_id_dao = IEnclaveIdentityDao::new(qe_dao_address, provider);
    let fmspc_tcb_dao = IFmspcTcbDao::new(tcb_dao_address, provider);
    let second_batch = provider
        .multicall()
        .address(multicall_address)
        .add(enclave_id_dao.getEnclaveIdentity(
            U256::from(enclave_id_number(requirements.qe_id_type)),
            U256::from(PCS_API_VERSION),
        ))
        .add(fmspc_tcb_dao.getTcbInfo(
            U256::from(requirements.tcb_type),
            requirements.fmspc.clone(),
            U256::from(TCB_VERSION),
        ));

    let (qe, tcb) = match second_batch.try_aggregate(false).await {
        Ok(results) => {
            let qe_read = retry_enclave_identity(
                results.0,
                provider,
                qe_dao_address,
                requirements.qe_id_type,
            );
            let tcb_read = retry_tcb_info(
                results.1,
                provider,
                tcb_dao_address,
                requirements.tcb_type,
                requirements.fmspc.as_str(),
            );
            tokio::join!(qe_read, tcb_read)
        }
        Err(_) => {
            let qe_read = get_enclave_identity_at_address(
                provider,
                qe_dao_address,
                requirements.qe_id_type,
                PCS_API_VERSION,
            );
            let tcb_read = get_tcb_info_at_address(
                provider,
                tcb_dao_address,
                requirements.tcb_type,
                requirements.fmspc.as_str(),
                TCB_VERSION,
            );
            tokio::join!(qe_read, tcb_read)
        }
    };

    CollateralReadResults {
        root,
        signing,
        pck,
        qe,
        tcb,
    }
}

async fn retry_certificate<P: Provider>(
    result: Result<
        automata_dcap_evm_bindings::r#i_pcs_dao::IPcsDao::getCertificateByIdReturn,
        alloy::providers::Failure,
    >,
    provider: &P,
    pcs_dao_address: Address,
    ca: CA,
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    match result {
        Ok(value) => Ok(certificate_from_return(value)),
        Err(_) => get_certificate_by_id_at_address(provider, pcs_dao_address, ca).await,
    }
}

async fn retry_enclave_identity<P: Provider>(
    result: Result<
        automata_dcap_evm_bindings::r#i_enclave_identity_dao::IEnclaveIdentityDao::EnclaveIdentityJsonObj,
        alloy::providers::Failure,
    >,
    provider: &P,
    dao_address: Address,
    id: EnclaveIdType,
) -> anyhow::Result<Vec<u8>> {
    match result {
        Ok(value) => enclave_identity_from_return(value),
        Err(_) => get_enclave_identity_at_address(provider, dao_address, id, PCS_API_VERSION).await,
    }
}

async fn retry_tcb_info<P: Provider>(
    result: Result<
        automata_dcap_evm_bindings::r#i_fmspc_tcb_dao::IFmspcTcbDao::TcbInfoJsonObj,
        alloy::providers::Failure,
    >,
    provider: &P,
    dao_address: Address,
    tcb_type: u8,
    fmspc: &str,
) -> anyhow::Result<Vec<u8>> {
    match result {
        Ok(value) => tcb_info_from_return(value),
        Err(_) => {
            get_tcb_info_at_address(provider, dao_address, tcb_type, fmspc, TCB_VERSION).await
        }
    }
}

fn enclave_id_number(id: EnclaveIdType) -> u8 {
    match id {
        EnclaveIdType::QE => 0,
        EnclaveIdType::QVE => 1,
        EnclaveIdType::TDQE => 2,
    }
}

fn versioned_lookup_errors(
    error: impl std::fmt::Display,
) -> (anyhow::Result<Vec<u8>>, anyhow::Result<Vec<u8>>) {
    let message = error.to_string();
    (
        Err(anyhow::anyhow!(
            "Failed to resolve QE identity DAO: {message}"
        )),
        Err(anyhow::anyhow!(
            "Failed to resolve FMSPC TCB DAO: {message}"
        )),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::Bytes;
    use alloy::providers::bindings::IMulticall3::{tryAggregateCall, Result as MulticallResult};
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

    fn load_tdx_quote() -> Vec<u8> {
        let cargo_manifest_dir = env!("CARGO_MANIFEST_DIR");
        let quote_path = format!("{cargo_manifest_dir}/../../samples/quotev4.hex");
        let quote_hex = std::fs::read_to_string(quote_path).unwrap();
        hex::decode(quote_hex.trim()).unwrap()
    }

    fn empty_pcs_return_data() -> Bytes {
        getCertificateByIdCall::abi_encode_returns(&getCertificateByIdReturn {
            cert: Bytes::new(),
            crl: Bytes::new(),
        })
        .into()
    }

    fn empty_enclave_identity_return_data() -> Bytes {
        getEnclaveIdentityCall::abi_encode_returns(&EnclaveIdentityJsonObj {
            identityStr: String::new(),
            signature: Bytes::new(),
        })
        .into()
    }

    fn empty_tcb_info_return_data() -> Bytes {
        getTcbInfoCall::abi_encode_returns(&TcbInfoJsonObj {
            tcbInfoStr: String::new(),
            signature: Bytes::new(),
        })
        .into()
    }

    fn success(return_data: Bytes) -> MulticallResult {
        MulticallResult {
            success: true,
            returnData: return_data,
        }
    }

    fn failure() -> MulticallResult {
        MulticallResult {
            success: false,
            returnData: Bytes::new(),
        }
    }

    fn push_multicall_response(asserter: &Asserter, results: Vec<MulticallResult>) {
        asserter.push_success(&Bytes::from(tryAggregateCall::abi_encode_returns(&results)));
    }

    fn push_single_batch(asserter: &Asserter, root: MulticallResult) {
        push_multicall_response(
            asserter,
            vec![
                root,
                success(empty_pcs_return_data()),
                success(empty_pcs_return_data()),
                success(empty_enclave_identity_return_data()),
                success(empty_tcb_info_return_data()),
            ],
        );
    }

    fn push_standard_batches(asserter: &Asserter) {
        push_multicall_response(
            asserter,
            vec![
                success(empty_pcs_return_data()),
                success(empty_pcs_return_data()),
                success(empty_pcs_return_data()),
                success(standardCall::abi_encode_returns(&19).into()),
            ],
        );
        push_multicall_response(
            asserter,
            vec![
                success(empty_enclave_identity_return_data()),
                success(empty_tcb_info_return_data()),
            ],
        );
    }

    fn push_direct_responses(asserter: &Asserter) {
        for _ in 0..3 {
            asserter.push_success(&empty_pcs_return_data());
        }
        asserter.push_success(&empty_enclave_identity_return_data());
        asserter.push_success(&empty_tcb_info_return_data());
    }

    fn reader<'a, P: Provider>(provider: &'a P, network: &Network) -> PccsReader<'a, P> {
        PccsReader::from_network(provider, network)
            .with_read_strategy(crate::PccsReadStrategy::multicall3())
    }

    #[tokio::test]
    async fn requested_evaluation_number_uses_one_multicall_request() {
        let network = Network::default_network(None).unwrap();
        let asserter = Asserter::new();
        push_single_batch(&asserter, success(empty_pcs_return_data()));
        asserter.push_success(&Bytes::new());
        let provider = ProviderBuilder::new().connect_mocked_client(asserter.clone());

        let result = reader(&provider, network)
            .find_missing_collaterals_from_quote(&load_tdx_quote(), false, Some(19))
            .await;

        assert!(matches!(result, Err(crate::CollateralError::Missing(_))));
        assert_eq!(asserter.read_q().len(), 1);
    }

    #[tokio::test]
    async fn standard_evaluation_number_uses_two_multicall_requests() {
        let network = Network::default_network(None).unwrap();
        let asserter = Asserter::new();
        push_standard_batches(&asserter);
        asserter.push_success(&Bytes::new());
        let provider = ProviderBuilder::new().connect_mocked_client(asserter.clone());

        let result = reader(&provider, network)
            .find_missing_collaterals_from_quote(&load_tdx_quote(), false, None)
            .await;

        assert!(matches!(result, Err(crate::CollateralError::Missing(_))));
        assert_eq!(asserter.read_q().len(), 1);
    }

    #[tokio::test]
    async fn failed_batch_falls_back_to_direct_concurrent_requests() {
        let network = Network::default_network(None).unwrap();
        let asserter = Asserter::new();
        asserter.push_failure_msg("Multicall3 is unavailable");
        push_direct_responses(&asserter);
        asserter.push_success(&Bytes::new());
        let provider = ProviderBuilder::new().connect_mocked_client(asserter.clone());

        let result = reader(&provider, network)
            .find_missing_collaterals_from_quote(&load_tdx_quote(), false, Some(19))
            .await;

        assert!(matches!(result, Err(crate::CollateralError::Missing(_))));
        assert_eq!(asserter.read_q().len(), 1);
    }

    #[tokio::test]
    async fn failed_inner_call_is_retried_once_directly() {
        let network = Network::default_network(None).unwrap();
        let asserter = Asserter::new();
        push_single_batch(&asserter, failure());
        asserter.push_success(&empty_pcs_return_data());
        asserter.push_success(&Bytes::new());
        let provider = ProviderBuilder::new().connect_mocked_client(asserter.clone());

        let result = reader(&provider, network)
            .find_missing_collaterals_from_quote(&load_tdx_quote(), false, Some(19))
            .await;

        assert!(matches!(result, Err(crate::CollateralError::Missing(_))));
        assert_eq!(asserter.read_q().len(), 1);
    }

    #[tokio::test]
    async fn failed_second_batch_retries_only_versioned_reads() {
        let network = Network::default_network(None).unwrap();
        let asserter = Asserter::new();
        push_multicall_response(
            &asserter,
            vec![
                success(empty_pcs_return_data()),
                success(empty_pcs_return_data()),
                success(empty_pcs_return_data()),
                success(standardCall::abi_encode_returns(&19).into()),
            ],
        );
        asserter.push_failure_msg("second Multicall3 batch failed");
        asserter.push_success(&empty_enclave_identity_return_data());
        asserter.push_success(&empty_tcb_info_return_data());
        asserter.push_success(&Bytes::new());
        let provider = ProviderBuilder::new().connect_mocked_client(asserter.clone());

        let result = reader(&provider, network)
            .find_missing_collaterals_from_quote(&load_tdx_quote(), false, None)
            .await;

        assert!(matches!(result, Err(crate::CollateralError::Missing(_))));
        assert_eq!(asserter.read_q().len(), 1);
    }
}
