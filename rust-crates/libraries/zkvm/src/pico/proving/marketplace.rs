use alloy::{
    primitives::{aliases::U96, Address, FixedBytes, U256},
    providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
    sol,
    transports::http::reqwest::Url,
};
use anyhow::{Context, Result};
use std::time::Duration;

use super::super::config::{
    MarketplaceConfig, DEFAULT_BREVIS_MARKET, DEFAULT_BREV_TOKEN, DEFAULT_STAKING_CONTROLLER,
};

/// Convert a u128 value to a U96, checking that it fits within 96 bits.
fn u128_to_u96(val: u128) -> Result<U96> {
    if val >= (1u128 << 96) {
        anyhow::bail!("Value {} exceeds uint96 range (max 2^96 - 1)", val);
    }
    Ok(U96::from_limbs([val as u64, (val >> 64) as u64]))
}

// BrevisMarket contract bindings (on-chain prover marketplace on Base)
sol! {
    #[sol(rpc)]
    interface IBrevisMarket {
        struct FeeParams {
            uint96 maxFee;
            uint96 minStake;
            uint64 deadline;
        }

        struct ProofRequest {
            uint64 nonce;
            bytes32 vk;
            bytes32 publicValuesDigest;
            string imgURL;
            bytes inputData;
            string inputURL;
            uint32 version;
            FeeParams fee;
        }

        struct GlobalStats {
            uint64 totalRequests;
            uint64 totalFulfilled;
            uint256 totalFees;
        }

        function requestProof(ProofRequest req) external;

        function getRequest(bytes32 reqid) external view returns (
            uint8 status,
            uint64 timestamp,
            address sender,
            uint256 maxFee,
            uint256 minStake,
            uint64 deadline,
            bytes32 vk,
            bytes32 publicValuesDigest,
            uint32 version
        );

        function getGlobalRecentStats() external view returns (GlobalStats memory stats, uint64 startAt);
        function getGlobalStatsTotal() external view returns (GlobalStats memory stats);
        function minMaxFee() external view returns (uint256);
        function maxMaxFee() external view returns (uint256);

        event NewRequest(bytes32 indexed reqid, ProofRequest req);
        event ProofSubmitted(bytes32 indexed reqid, address indexed prover, uint256[8] proof, uint256 actualFee);
    }

    #[sol(rpc)]
    interface IERC20 {
        function approve(address spender, uint256 amount) external returns (bool);
    }

    #[sol(rpc)]
    interface IStakingController {
        function minSelfStake() external view returns (uint256);
    }
}

/// Request status values from the BrevisMarket contract.
/// Mirrors the on-chain `ReqStatus` enum: Pending, Fulfilled, Refunded, Slashed.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestStatus {
    Pending = 0,
    Fulfilled = 1,
    Refunded = 2,
    Slashed = 3,
}

impl TryFrom<u8> for RequestStatus {
    type Error = anyhow::Error;
    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(RequestStatus::Pending),
            1 => Ok(RequestStatus::Fulfilled),
            2 => Ok(RequestStatus::Refunded),
            3 => Ok(RequestStatus::Slashed),
            _ => anyhow::bail!("Unknown request status: {}", value),
        }
    }
}

/// Submit a proof request to the Brevis Prover Network marketplace on Base
/// and poll until a prover fulfills it, then return the Groth16 proof bytes.
///
/// # Flow
/// 1. Resolve max_fee (use provided value or auto-estimate from on-chain stats)
/// 2. Approve BREV token spending on the BrevisMarket contract
/// 3. Submit a `requestProof` transaction with the ELF URL, VK, and fee params
/// 4. Parse the `NewRequest` event to extract the request ID
/// 5. Poll `getRequest()` until the status indicates fulfillment
/// 6. Query `ProofSubmitted` event logs to extract the proof
/// 7. Return the proof as 256 bytes (8 × 32 bytes)
pub async fn prove_with_marketplace(
    _elf: &'static [u8],
    input_bytes: &[u8],
    vk: [u8; 32],
    public_values_digest: [u8; 32],
    config: &MarketplaceConfig,
) -> Result<Vec<u8>> {
    // --- Validate config ---
    let rpc_url = config
        .rpc_url
        .as_ref()
        .context("--pico-rpc-url or PICO_RPC_URL is required for marketplace strategy")?;
    let private_key_hex = config
        .private_key
        .as_ref()
        .context("--pico-prover-key or PICO_PROVER_KEY is required for marketplace strategy")?;

    let rpc_url_parsed: Url = rpc_url.parse().context("Invalid RPC URL format")?;

    let brevis_market_addr: Address = config
        .brevis_market_address
        .as_deref()
        .unwrap_or(DEFAULT_BREVIS_MARKET)
        .parse()
        .context("Invalid BrevisMarket address")?;

    let brev_token_addr: Address = config
        .brev_token_address
        .as_deref()
        .unwrap_or(DEFAULT_BREV_TOKEN)
        .parse()
        .context("Invalid BREV token address")?;

    let staking_controller_addr: Address = config
        .staking_controller_address
        .as_deref()
        .unwrap_or(DEFAULT_STAKING_CONTROLLER)
        .parse()
        .context("Invalid StakingController address")?;

    let poll_interval = Duration::from_secs(config.poll_interval.unwrap_or(30));
    let version = config.version.unwrap_or(0);

    // --- Setup Alloy provider + signer ---
    let private_key_hex = private_key_hex.strip_prefix("0x").unwrap_or(private_key_hex);
    let signer: PrivateKeySigner = private_key_hex
        .parse()
        .context("Failed to parse private key")?;

    let provider = ProviderBuilder::new()
        .wallet(signer)
        .connect_http(rpc_url_parsed);

    log::info!(
        "Connected to Base RPC. BrevisMarket: {}, BREV: {}",
        brevis_market_addr,
        brev_token_addr
    );

    // --- Create BrevisMarket instance early (needed for fee estimation) ---
    let brevis_market = IBrevisMarket::new(brevis_market_addr, &provider);

    // --- Step 1: Resolve max_fee ---
    let resolved_max_fee: u128 = match config.max_fee {
        Some(fee) => {
            println!(
                "Using provided max fee: {} wei ({:.6} BREV)",
                fee,
                fee as f64 / 1e18
            );
            fee
        }
        None => {
            let multiplier = config.fee_multiplier.unwrap_or(3.0);
            println!("Auto-estimating max fee from on-chain marketplace stats...");

            // Query fee boundaries
            let min_max_fee: u128 = brevis_market
                .minMaxFee()
                .call()
                .await
                .context("Failed to query minMaxFee")?
                .try_into()
                .context("minMaxFee exceeds u128")?;

            let max_max_fee: u128 = brevis_market
                .maxMaxFee()
                .call()
                .await
                .context("Failed to query maxMaxFee")?
                .try_into()
                .context("maxMaxFee exceeds u128")?;

            log::info!(
                "Fee boundaries: minMaxFee={} wei, maxMaxFee={} wei",
                min_max_fee,
                max_max_fee
            );

            // Step 1: Try recent stats
            let baseline = match brevis_market.getGlobalRecentStats().call().await {
                Ok(result) => {
                    let stats = result.stats;
                    if stats.totalFulfilled > 0 {
                        let avg: u128 = stats
                            .totalFees
                            .try_into()
                            .context("totalFees exceeds u128")?;
                        let avg = avg / stats.totalFulfilled as u128;
                        println!(
                            "  Recent stats: {} fulfilled, avg fee {} wei ({:.6} BREV)",
                            stats.totalFulfilled,
                            avg,
                            avg as f64 / 1e18
                        );
                        Some(avg)
                    } else {
                        println!("  No recently fulfilled requests, checking total stats...");
                        None
                    }
                }
                Err(e) => {
                    log::warn!("Failed to query getGlobalRecentStats: {}", e);
                    None
                }
            };

            // Step 2: Fallback to total stats
            let baseline = match baseline {
                Some(b) => b,
                None => match brevis_market.getGlobalStatsTotal().call().await {
                    Ok(stats) => {
                        if stats.totalFulfilled > 0 {
                            let avg: u128 = stats
                                .totalFees
                                .try_into()
                                .context("totalFees exceeds u128")?;
                            let avg = avg / stats.totalFulfilled as u128;
                            println!(
                                "  Total stats: {} fulfilled, avg fee {} wei ({:.6} BREV)",
                                stats.totalFulfilled,
                                avg,
                                avg as f64 / 1e18
                            );
                            avg
                        } else {
                            println!(
                                "  No fulfilled requests found at all, using minMaxFee as baseline"
                            );
                            min_max_fee
                        }
                    }
                    Err(e) => {
                        log::warn!(
                            "Failed to query getGlobalStatsTotal: {}, using minMaxFee as baseline",
                            e
                        );
                        min_max_fee
                    }
                },
            };

            // Apply multiplier and enforce minMaxFee floor
            let estimated = (baseline as f64 * multiplier) as u128;
            let estimated = estimated.max(min_max_fee);

            // Clamp to maxMaxFee ceiling (if non-zero)
            let estimated = if max_max_fee > 0 {
                estimated.min(max_max_fee)
            } else {
                estimated
            };

            println!(
                "  Estimated max fee: {} wei ({:.6} BREV) (baseline × {:.1}, clamped to [{:.6}, {}] BREV)",
                estimated,
                estimated as f64 / 1e18,
                multiplier,
                min_max_fee as f64 / 1e18,
                if max_max_fee > 0 {
                    format!("{:.6}", max_max_fee as f64 / 1e18)
                } else {
                    "∞".to_string()
                },
            );

            estimated
        }
    };

    // --- Step 2: Approve BREV token spending ---
    let max_fee_u256 = U256::from(resolved_max_fee);

    let brev_token = IERC20::new(brev_token_addr, &provider);
    println!(
        "Approving BREV token spending ({} wei)...",
        resolved_max_fee
    );

    let approve_call = brev_token.approve(brevis_market_addr, max_fee_u256);
    let pending_tx = approve_call
        .send()
        .await
        .context("Failed to send BREV approve transaction")?;

    let approve_receipt = pending_tx
        .get_receipt()
        .await
        .context("Failed to get approve transaction receipt")?;

    if !approve_receipt.status() {
        anyhow::bail!("BREV token approve transaction reverted");
    }
    log::info!(
        "BREV approve confirmed in tx: {:?}",
        approve_receipt.transaction_hash
    );

    // --- Step 3: Build and submit proof request ---
    // Resolve minStake: use provided value, or query StakingController.minSelfStake() on-chain
    let min_stake = match config.min_stake {
        Some(val) => val,
        None => {
            println!(
                "No --min-stake provided, querying StakingController({})...",
                staking_controller_addr
            );
            let staking_controller =
                IStakingController::new(staking_controller_addr, &provider);
            let min_self_stake = staking_controller
                .minSelfStake()
                .call()
                .await
                .context("Failed to query minSelfStake from StakingController")?;
            let val: u128 = min_self_stake
                .try_into()
                .context("minSelfStake value exceeds u128")?;
            println!(
                "Using on-chain minSelfStake: {} wei ({} BREV)",
                val,
                val / 1_000_000_000_000_000_000
            );
            val
        }
    };

    let fee_params = IBrevisMarket::FeeParams {
        maxFee: u128_to_u96(resolved_max_fee).context("max_fee exceeds uint96")?,
        minStake: u128_to_u96(min_stake).context("min_stake exceeds uint96")?,
        deadline: config.deadline,
    };

    // For inputData: if an input_url is provided, we can send empty bytes and rely on the URL.
    // Otherwise, send the actual input bytes.
    let input_data = if config.input_url.is_some() {
        vec![]
    } else {
        input_bytes.to_vec()
    };

    let proof_request = IBrevisMarket::ProofRequest {
        nonce: config.nonce,
        vk: FixedBytes::from(vk),
        publicValuesDigest: FixedBytes::from(public_values_digest),
        imgURL: config.elf_url.clone(),
        inputData: input_data.into(),
        inputURL: config.input_url.clone().unwrap_or_default(),
        version,
        fee: fee_params,
    };

    println!("Submitting proof request to BrevisMarket...");
    let request_call = brevis_market.requestProof(proof_request);
    let pending_tx = request_call
        .send()
        .await
        .context("Failed to send requestProof transaction")?;

    let request_receipt = pending_tx
        .get_receipt()
        .await
        .context("Failed to get requestProof transaction receipt")?;

    if !request_receipt.status() {
        anyhow::bail!("requestProof transaction reverted");
    }
    log::info!(
        "requestProof confirmed in tx: {:?}",
        request_receipt.transaction_hash
    );

    // --- Step 4: Parse NewRequest event to get reqid ---
    let new_request_events: Vec<_> = request_receipt
        .inner
        .logs()
        .iter()
        .filter_map(|log| log.log_decode::<IBrevisMarket::NewRequest>().ok())
        .collect();

    let reqid = new_request_events
        .first()
        .context("No NewRequest event found in transaction receipt")?
        .inner
        .data
        .reqid;

    println!(
        "Proof request submitted! Request ID: 0x{}",
        hex::encode(reqid)
    );

    // --- Step 5: Poll getRequest() until fulfilled ---
    println!(
        "Polling for proof fulfillment (interval: {}s)...",
        poll_interval.as_secs()
    );

    let submission_time = std::time::Instant::now();
    let mut diagnostics_printed = false;
    // Bidding phase is typically 300s (5 min) on Brevis ProverNet
    let bidding_phase_secs = 300u64;

    loop {
        tokio::time::sleep(poll_interval).await;

        let result = brevis_market
            .getRequest(reqid)
            .call()
            .await
            .context("Failed to call getRequest")?;

        let status = RequestStatus::try_from(result.status)?;
        log::info!("Request status: {:?}", status);

        match status {
            RequestStatus::Fulfilled => {
                println!("Proof has been fulfilled!");
                break;
            }
            RequestStatus::Refunded => {
                anyhow::bail!("Proof request was refunded (deadline passed or cancelled)");
            }
            RequestStatus::Slashed => {
                anyhow::bail!("Assigned prover was slashed (failed to deliver proof in time)");
            }
            RequestStatus::Pending => {
                println!("Status: pending (awaiting prover bids / proof generation) ...");

                // One-time diagnostic hint after the bidding phase ends with no progress
                if !diagnostics_printed
                    && submission_time.elapsed().as_secs() > bidding_phase_secs
                {
                    diagnostics_printed = true;
                    println!();
                    println!(
                        "╭─ Diagnostic ───────────────────────────────────────────────╮"
                    );
                    println!(
                        "│ No progress after the bidding phase ({bidding_phase_secs}s).              │"
                    );
                    println!(
                        "│                                                            │"
                    );
                    println!(
                        "│ This may indicate that no provers on the network currently  │"
                    );
                    println!(
                        "│ support Pico zkVM (version {version}).                              │"
                    );
                    println!(
                        "│                                                            │"
                    );
                    println!(
                        "│ Suggestions:                                                │"
                    );
                    println!(
                        "│  • Check the ProverNet dashboard:                           │"
                    );
                    println!(
                        "│    https://provernet.brevis.network/                        │"
                    );
                    println!(
                        "│  • Verify your ELF URL is publicly accessible               │"
                    );
                    println!(
                        "│  • Consider using local proving (--strategy local) instead   │"
                    );
                    println!(
                        "╰────────────────────────────────────────────────────────────╯"
                    );
                    println!();
                }
            }
        }
    }

    // --- Step 6: Query ProofSubmitted event to extract proof ---
    let block_number = request_receipt.block_number.unwrap_or(0);
    let filter = brevis_market
        .ProofSubmitted_filter()
        .topic1(reqid)
        .from_block(block_number);

    let events = filter
        .query()
        .await
        .context("Failed to query ProofSubmitted events")?;

    let proof_event = events
        .first()
        .context("No ProofSubmitted event found for this request")?;

    let proof_u256_array = &proof_event.0.proof;
    log::info!(
        "Proof submitted by prover: {:?}, actual fee: {}",
        proof_event.0.prover,
        proof_event.0.actualFee
    );

    // --- Step 7: Encode proof as 256 bytes (8 × 32 bytes) ---
    let mut proof_bytes = Vec::with_capacity(8 * 32);
    for val in proof_u256_array.iter() {
        proof_bytes.extend_from_slice(&val.to_be_bytes::<32>());
    }

    println!(
        "Proof retrieved successfully ({} bytes)",
        proof_bytes.len()
    );

    Ok(proof_bytes)
}
