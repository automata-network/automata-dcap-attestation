use crate::version::Version;
use alloy::sol_types::SolValue;
use anyhow::{Context, Result};
use dcap_rs::types::{
    quote::{Quote, QuoteBody},
    report::{EnclaveReportBody, Td10ReportBody},
    VerifiedOutput,
};

/// Parse raw quote bytes into a Quote structure
///
/// # Arguments
/// * `quote_bytes` - Raw quote bytes to parse
///
/// # Returns
/// Parsed Quote structure
pub fn parse_quote<'a>(quote_bytes: &'a [u8]) -> Result<Quote<'a>> {
    let mut bytes_ref = quote_bytes;
    Quote::read(&mut bytes_ref)
}

/// Parse raw output bytes into a version-aware VerifiedOutput structure
///
/// # Arguments
/// * `output_bytes` - Raw output bytes to parse
/// * `version` - Version of the deployment (v1.0 or v1.1)
///
/// # Returns
/// Parsed VerifiedOutput structure (version-aware)
pub fn parse_output(output_bytes: &[u8], version: Version) -> Result<VerifiedOutput> {
    match version {
        Version::V1_0 => parse_legacy_output(output_bytes),
        Version::V1_1 => Ok(VerifiedOutput::from_bytes(output_bytes)?),
    }
}

fn parse_legacy_output(output_bytes: &[u8]) -> Result<VerifiedOutput> {
    let header = output_bytes
        .get(..13)
        .context("legacy verified output is shorter than its 13-byte header")?;
    let quote_version = header[0..2]
        .try_into()
        .context("legacy quote version has the wrong length")?;
    let tee_type = header[2..6]
        .try_into()
        .context("legacy TEE type has the wrong length")?;
    let tcb_status = header[6];
    let fmspc = header[7..13]
        .try_into()
        .context("legacy FMSPC has the wrong length")?;

    let mut offset = 13usize;
    let (quote_body_type, quote_body) = match u32::from_le_bytes(tee_type) {
        0x00000000 => {
            let end = offset
                .checked_add(384)
                .context("legacy SGX quote body offset overflow")?;
            let raw_quote_body = output_bytes
                .get(offset..end)
                .context("legacy verified output has a truncated 384-byte SGX quote body")?;
            offset += 384;
            let body_array: [u8; 384] = raw_quote_body.try_into()?;
            (
                1u16,
                QuoteBody::SgxQuoteBody(EnclaveReportBody::try_from(body_array)?),
            )
        }
        0x00000081 => {
            let end = offset
                .checked_add(584)
                .context("legacy TDX quote body offset overflow")?;
            let raw_quote_body = output_bytes
                .get(offset..end)
                .context("legacy verified output has a truncated 584-byte TDX quote body")?;
            offset += 584;
            let body_array: [u8; 584] = raw_quote_body.try_into()?;
            (
                2u16,
                QuoteBody::Td10QuoteBody(Td10ReportBody::try_from(body_array)?),
            )
        }
        _ => anyhow::bail!("unsupported tee type in legacy output"),
    };

    let mut advisory_ids = None;
    if offset < output_bytes.len() {
        let advisory_ids_slice = &output_bytes[offset..];
        advisory_ids = Some(
            <Vec<String>>::abi_decode(advisory_ids_slice)
                .context("legacy advisory ID ABI data is malformed")?,
        );
    }

    Ok(VerifiedOutput {
        quote_version: u16::from_be_bytes(quote_version),
        quote_body_type,
        tcb_status,
        fmspc,
        quote_body,
        advisory_ids,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_parser_returns_errors_for_truncated_inputs() {
        for input in [Vec::new(), vec![0; 12], vec![0; 13], vec![0; 13 + 383]] {
            let result = std::panic::catch_unwind(|| parse_output(&input, Version::V1_0));
            assert!(
                result.is_ok(),
                "legacy parser panicked for {} bytes",
                input.len()
            );
            assert!(
                result.unwrap().is_err(),
                "legacy parser accepted {} truncated bytes",
                input.len()
            );
        }
    }

    #[test]
    fn legacy_parser_returns_error_for_malformed_advisory_ids() {
        let mut input = vec![0; 13 + 384];
        input[0..2].copy_from_slice(&3u16.to_be_bytes());
        input.extend_from_slice(&[1, 2, 3]);

        let result = std::panic::catch_unwind(|| parse_output(&input, Version::V1_0));
        assert!(result.is_ok(), "legacy advisory parser panicked");
        assert!(result.unwrap().is_err());
    }
}
