//! Direct calls to FeeV2. No portal involvement, no output down-conversion.
use crate::ZkCoprocessor;
use alloy::{
    primitives::{Address, Bytes, B256},
    providers::Provider,
};
use anyhow::{ensure, Result};
use automata_dcap_evm_bindings::v2::IAutomataDcapAttestationV2;
use automata_dcap_utils::parser::parse_output_v2;

pub async fn verify_and_attest_on_chain_v2<P: Provider>(
    provider: &P,
    contract_address: Address,
    quote: &[u8],
    tcb_eval: u32,
) -> Result<Bytes> {
    let contract = IAutomataDcapAttestationV2::new(contract_address, provider);
    let result = contract
        .verifyAndAttestOnChainV2(Bytes::copy_from_slice(quote), tcb_eval)
        .call()
        .await?;
    ensure!(
        result.success,
        "V2 verification failed: {}",
        String::from_utf8_lossy(&result.output)
    );
    parse_output_v2(&result.output)?;
    Ok(result.output)
}

pub async fn verify_and_attest_with_zk_proof_v2<P: Provider>(
    provider: &P,
    contract_address: Address,
    journal: &[u8],
    backend: ZkCoprocessor,
    proof: &[u8],
    program_identifier: Option<B256>,
    tcb_eval: u32,
) -> Result<Bytes> {
    parse_output_v2(journal)?;
    ensure!(backend != ZkCoprocessor::None, "ZK backend is required");
    let contract = IAutomataDcapAttestationV2::new(contract_address, provider);
    let identifier = match program_identifier {
        Some(id) => id,
        None => contract.programIdentifierV2(backend.into()).call().await?,
    };
    let result = contract
        .verifyAndAttestWithZKProofV2(
            Bytes::copy_from_slice(journal),
            backend.into(),
            Bytes::copy_from_slice(proof),
            identifier,
            tcb_eval,
        )
        .call()
        .await?;
    ensure!(
        result.success,
        "V2 verification failed: {}",
        String::from_utf8_lossy(&result.output)
    );
    ensure!(
        result.output.as_ref() == journal,
        "FeeV2 returned bytes different from the proven journal"
    );
    Ok(result.output)
}
