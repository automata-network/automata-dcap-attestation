mod pccs_client;
mod verifier_client;
mod models;
mod utils;

use std::ops::Deref;

use anchor_client::solana_sdk::{signature::Signature, signer::Signer};
use anchor_lang::prelude::Pubkey;
pub use pccs_client::*;
pub use verifier_client::*;
pub use models::*;
pub use utils::*;


/// Verify a quote and return the verified output address and the signatures.
pub async fn verify_quote<S: Clone + Deref<Target = impl Signer>>(
    bytes: &[u8],
    signer:  S
) -> anyhow::Result<(Pubkey, Vec<Signature>)> {

    let verifier_client = VerifierClient::new(signer)?;

    let quote_buffer_pubkey = verifier_client.init_quote_buffer(
        bytes.len() as u32,
        get_num_chunks(bytes.len(), 512),
    ).await?;

    verifier_client.upload_chunks(
        quote_buffer_pubkey,
        bytes,
        512,
    ).await?;

    let signatures = verifier_client.verify_quote(
        quote_buffer_pubkey,
    ).await?;

    let verified_output_pubkey = verifier_client.get_verified_output_pubkey(
        quote_buffer_pubkey,
    ).await?;

    Ok((verified_output_pubkey, signatures))
}
