//! Direct calls to AutomataDcapAttestationV2. No portal or output down-conversion.
use crate::ZkCoprocessor;
use alloy::{
    primitives::{Address, B256, Bytes},
    providers::Provider,
};
use anyhow::{Result, ensure};
use automata_dcap_evm_bindings::v2::IAutomataDcapAttestationV2;
use automata_dcap_utils::parser::parse_output_v2;

/// Body is returned separately, bound to the compact output by Keccak-256.
#[derive(Debug, Clone)]
pub struct RawVerificationV2 {
    pub output: Bytes,
    pub quote_body: Bytes,
}

/// `min_check` skips workload attributes only; pass false for strict verification.
pub async fn verify_and_attest_on_chain_v2<P: Provider>(
    provider: &P,
    contract_address: Address,
    quote: &[u8],
    tcb_eval: u32,
    min_check: bool,
) -> Result<RawVerificationV2> {
    let contract = IAutomataDcapAttestationV2::new(contract_address, provider);
    let result = contract
        .verifyAndAttestOnChainV2(Bytes::copy_from_slice(quote), tcb_eval, min_check)
        .call()
        .await?;
    ensure!(
        result.success,
        "V2 verification failed: {}",
        String::from_utf8_lossy(&result.output)
    );
    let output = parse_output_v2(&result.output)?;
    output.validate_quote_body(&result.quoteBody)?;
    Ok(RawVerificationV2 {
        output: result.output,
        quote_body: result.quoteBody,
    })
}

/// Proof/journal/collateral validation is mandatory in both modes. Minimal mode
/// leaves only the workload attribute checks to the application.
pub async fn verify_and_attest_with_zk_proof_v2<P: Provider>(
    provider: &P,
    contract_address: Address,
    journal: &[u8],
    backend: ZkCoprocessor,
    proof: &[u8],
    program_identifier: Option<B256>,
    tcb_eval: u32,
    min_check: bool,
) -> Result<Bytes> {
    parse_output_v2(journal)?;
    ensure!(backend != ZkCoprocessor::None, "ZK backend is required");
    ensure!(
        !min_check || program_identifier.is_some(),
        "minimal verification requires an explicit minimal program ID"
    );
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
            min_check,
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
