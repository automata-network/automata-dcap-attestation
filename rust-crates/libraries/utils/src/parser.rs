use crate::version::Version;
use alloy::sol_types::SolValue;
use anyhow::Result;
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
        Version::V1_0 => {
            parse_legacy_output(output_bytes)
        }
        Version::V1_1 => {
            Ok(VerifiedOutput::from_bytes(output_bytes)?)
        }
    }
}

fn parse_legacy_output(output_bytes: &[u8]) -> Result<VerifiedOutput> {
    let mut quote_version = [0; 2];
    quote_version.copy_from_slice(&output_bytes[0..2]);
    let mut tee_type = [0; 4];
    tee_type.copy_from_slice(&output_bytes[2..6]);
    let tcb_status = output_bytes[6];
    let mut fmspc = [0; 6];
    fmspc.copy_from_slice(&output_bytes[7..13]);

    let mut offset = 13usize;
    let (quote_body_type, quote_body) = match u32::from_le_bytes(tee_type) {
        0x00000000 => {
            let raw_quote_body = &output_bytes[offset..offset + 384];
            offset += 384;
            let body_array: [u8; 384] = raw_quote_body.try_into()?;
            (
                1u16,
                QuoteBody::SgxQuoteBody(EnclaveReportBody::try_from(body_array)?),
            )
        }
        0x00000081 => {
            let raw_quote_body = &output_bytes[offset..offset + 584];
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
        advisory_ids = Some(<Vec<String>>::abi_decode(advisory_ids_slice).unwrap());
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
