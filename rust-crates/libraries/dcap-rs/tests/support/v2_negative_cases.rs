//! Shared diagnostic input mutations; never used by the production guest.
use alloy_sol_types::SolType;
use anyhow::Result;
use dcap_rs::types::quote::Quote;

type GuestInput = alloy_sol_types::sol!((bytes, bytes, uint64));

pub fn negative_inputs(input: &[u8]) -> Result<Vec<(&'static str, Vec<u8>)>> {
    let (collateral, quote, timestamp) = GuestInput::abi_decode_params(input)?;
    let parsed = Quote::read(&mut quote.as_ref())?;
    let signature_length_offset = if parsed.header.version.get() <= 4 {
        48
    } else {
        54
    } + parsed.body_size as usize;
    let mut mutations = Vec::new();
    let mut body = quote.to_vec();
    body[80] ^= 1;
    mutations.push(("tampered-signed-body", body));
    let mut signature = quote.to_vec();
    signature[signature_length_offset + 4] ^= 1;
    mutations.push(("tampered-quote-signature", signature));
    let mut padded = quote.to_vec();
    padded.extend_from_slice(&[0; 3065]);
    mutations.push(("trailing-zero-padding", padded));
    mutations.push(("truncated-quote", quote[..quote.len() - 1].to_vec()));
    let mut version = quote.to_vec();
    version[..2].copy_from_slice(&2u16.to_le_bytes());
    mutations.push(("unsupported-quote-version", version));
    let mut length = quote.to_vec();
    length[signature_length_offset..signature_length_offset + 4]
        .copy_from_slice(&u32::MAX.to_le_bytes());
    mutations.push(("oversized-signature-length", length));
    let mut out: Vec<_> = mutations
        .into_iter()
        .map(|(name, quote)| {
            (
                name,
                GuestInput::abi_encode_params(&(collateral.clone(), quote, timestamp)),
            )
        })
        .collect();
    out.push((
        "pre-validity-timestamp",
        GuestInput::abi_encode_params(&(collateral.clone(), quote.clone(), 0u64)),
    ));
    out.push((
        "post-validity-timestamp",
        GuestInput::abi_encode_params(&(
            collateral,
            quote,
            timestamp
                .checked_add(400 * 86400)
                .expect("fixture timestamp"),
        )),
    ));
    Ok(out)
}
