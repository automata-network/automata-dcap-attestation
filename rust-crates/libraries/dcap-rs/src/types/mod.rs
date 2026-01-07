use alloy_sol_types::SolValue;
use anyhow::Result;
use quote::QuoteBody;
use serde::{Deserialize, Serialize};

use super::types::report::{EnclaveReportBody, Td10ReportBody, Td15ReportBody};

#[cfg(feature = "full")]
pub mod collateral;
#[cfg(feature = "full")]
pub mod enclave_identity;
pub mod pod;
pub mod quote;
pub mod report;
pub mod sgx_x509;
#[cfg(feature = "full")]
pub mod tcb_info;

const ENCLAVE_REPORT_LEN: usize = 384; // SGX_ENCLAVE_REPORT
const TD10_REPORT_LEN: usize = 584; // TD10_REPORT
const TD15_REPORT_LEN: usize = 648; // TD15_REPORT

// serialization:
// [quote_version][quote_body_type][tcb_status][fmspc][quote_body_raw_bytes][abi-encoded string array
// of tcb_advisory_ids] 2 bytes + 2 bytes + 1 byte + 6 bytes + var (SGX_ENCLAVE_REPORT = 384;
// TD10_REPORT = 584; TD15_REPORT = 648) + var total: 11 + (384 or 584 or 648) + var bytes
#[derive(Debug, Serialize, Deserialize)]
pub struct VerifiedOutput {
    pub quote_version: u16,
    pub quote_body_type: u16,
    pub tcb_status: u8,
    #[serde(with = "crate::utils::serde_arrays")]
    pub fmspc: [u8; 6],
    pub quote_body: QuoteBody,
    pub advisory_ids: Option<Vec<String>>,
}

impl VerifiedOutput {
    pub fn to_vec(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.quote_version.to_be_bytes());
        bytes.extend_from_slice(&self.quote_body_type.to_be_bytes());
        bytes.push(self.tcb_status);
        bytes.extend_from_slice(&self.fmspc);
        bytes.extend_from_slice(self.quote_body.as_bytes());

        if let Some(ref ids) = self.advisory_ids {
            let encoded = ids.abi_encode();
            bytes.extend_from_slice(&encoded);
        }

        bytes
    }

    pub fn from_bytes(slice: &[u8]) -> Result<VerifiedOutput> {
        let mut quote_version = [0; 2];
        quote_version.copy_from_slice(&slice[0..2]);
        let mut quote_body_type = [0; 2];
        quote_body_type.copy_from_slice(&slice[2..4]);
        let tcb_status = slice[4];
        let mut fmspc = [0; 6];
        fmspc.copy_from_slice(&slice[5..11]);

        let mut offset = 11usize;
        let quote_body_type = u16::from_be_bytes(quote_body_type);
        let quote_body = match quote_body_type {
            1 => {
                let raw_quote_body: [u8; ENCLAVE_REPORT_LEN] = slice
                    [offset..offset + ENCLAVE_REPORT_LEN]
                    .try_into()
                    .unwrap();
                offset += ENCLAVE_REPORT_LEN;
                QuoteBody::SgxQuoteBody(EnclaveReportBody::try_from(raw_quote_body)?)
            },
            2 => {
                let raw_quote_body: [u8; TD10_REPORT_LEN] =
                    slice[offset..offset + TD10_REPORT_LEN].try_into()?;
                offset += TD10_REPORT_LEN;
                QuoteBody::Td10QuoteBody(Td10ReportBody::try_from(raw_quote_body)?)
            },
            3 => {
                let raw_quote_body: [u8; TD15_REPORT_LEN] =
                    slice[offset..offset + TD15_REPORT_LEN].try_into()?;
                offset += TD15_REPORT_LEN;
                QuoteBody::Td15QuoteBody(Td15ReportBody::try_from(raw_quote_body)?)
            },
            _ => panic!("unknown QuoteBody type"),
        };

        let mut advisory_ids = None;
        if offset < slice.len() {
            let advisory_ids_slice = &slice[offset..];
            advisory_ids = Some(<Vec<String>>::abi_decode(advisory_ids_slice)?);
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
}

impl std::fmt::Display for VerifiedOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Verified Output:")?;
        writeln!(f, "  Quote Version: {}", self.quote_version)?;
        writeln!(
            f,
            "  Quote Body Type: {} ({})",
            self.quote_body_type,
            match self.quote_body_type {
                1 => "SGX",
                2 => "TDX 1.0",
                3 => "TDX 1.5",
                _ => "Unknown",
            }
        )?;
        writeln!(
            f,
            "  TCB Status: 0x{:02x} ({})",
            self.tcb_status,
            match self.tcb_status {
                0 => "UpToDate",
                1 => "OutOfDate",
                2 => "ConfigurationNeeded",
                3 => "OutOfDateConfigurationNeeded",
                4 => "SWHardeningNeeded",
                5 => "ConfigurationAndSWHardeningNeeded",
                _ => "Unknown/Invalid",
            }
        )?;
        writeln!(f, "  FMSPC: {}", hex::encode(self.fmspc))?;

        match &self.quote_body {
            QuoteBody::SgxQuoteBody(body) => {
                writeln!(f, "  SGX Quote Body:")?;
                writeln!(f, "    MR_ENCLAVE: {}", hex::encode(body.mr_enclave))?;
                writeln!(f, "    MR_SIGNER: {}", hex::encode(body.mr_signer))?;
                writeln!(f, "    ISV_PROD_ID: {}", body.isv_prod_id)?;
                writeln!(f, "    ISV_SVN: {}", body.isv_svn)?;
                writeln!(
                    f,
                    "    USER REPORT_DATA: {}",
                    hex::encode(body.user_report_data)
                )?;
            },
            QuoteBody::Td10QuoteBody(body) => {
                writeln!(f, "  TDX TD10 Quote Body:")?;
                writeln!(f, "    MR_TD: {}", hex::encode(body.mr_td))?;
                writeln!(f, "    RTMR0: {}", hex::encode(body.rtm_r0))?;
                writeln!(f, "    RTMR1: {}", hex::encode(body.rtm_r1))?;
                writeln!(f, "    RTMR2: {}", hex::encode(body.rtm_r2))?;
                writeln!(f, "    RTMR3: {}", hex::encode(body.rtm_r3))?;
                writeln!(
                    f,
                    "    USER REPORT_DATA: {}",
                    hex::encode(body.user_report_data)
                )?;
            },
            QuoteBody::Td15QuoteBody(body) => {
                writeln!(f, "  TDX TD15 Quote Body:")?;
                writeln!(
                    f,
                    "    TEE_TCB_SVN: {}",
                    hex::encode(body.td_report.tee_tcb_svn)
                )?;
                writeln!(f, "    TEE_TCB_SVN2: {}", hex::encode(body.tee_tcb_svn2))?;
                writeln!(f, "    MR_TD: {}", hex::encode(body.td_report.mr_td))?;
                writeln!(f, "    MR_SERVICE_TD: {}", hex::encode(body.mr_service_td))?;
                writeln!(f, "    RTMR0: {}", hex::encode(body.td_report.rtm_r0))?;
                writeln!(f, "    RTMR1: {}", hex::encode(body.td_report.rtm_r1))?;
                writeln!(f, "    RTMR2: {}", hex::encode(body.td_report.rtm_r2))?;
                writeln!(f, "    RTMR3: {}", hex::encode(body.td_report.rtm_r3))?;
                writeln!(
                    f,
                    "    USER REPORT_DATA: {}",
                    hex::encode(body.td_report.user_report_data)
                )?;
            },
        }

        if let Some(ref advisory_ids) = self.advisory_ids {
            if !advisory_ids.is_empty() {
                writeln!(f, "  Advisory IDs:")?;
                for id in advisory_ids {
                    writeln!(f, "    - {}", id)?;
                }
            }
        }

        Ok(())
    }
}
