#[cfg(test)]
mod verifier;

#[cfg(test)]
mod pccs;

use anchor_client::solana_sdk::pubkey::Pubkey;

pub const TEST_RISC0_VERIFIER_PUBKEY: Pubkey = Pubkey::from_str_const("5Gxa8YTih2rg3NY5EuWLtpS3Eq5xpS7PKWxspAAni5RS");