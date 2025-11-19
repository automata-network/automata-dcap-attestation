//! Serializable wrappers for DCAP Quote types
//!
//! This module provides owned, serializable versions of the zero-copy Quote types
//! from dcap-rs. These wrappers are specifically designed for WASM/JavaScript interop
//! and convert borrowed slices to owned Vec<u8> for serialization.

use dcap_rs::types::{quote::*, report::*};
use serde::{Deserialize, Serialize};

/// Owned, serializable wrapper around Quote for WASM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteWrapper {
    pub header: QuoteHeaderWrapper,
    pub body_type: u16,
    pub body_size: u32,
    pub body: QuoteBody,
    pub signature: QuoteSignatureDataWrapper,
}

/// Owned wrapper for QuoteHeader
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteHeaderWrapper {
    pub version: u16,
    pub attestation_key_type: u16,
    pub tee_type: u32,
    pub qe_svn: u16,
    pub pce_svn: u16,
    pub qe_vendor_id: [u8; 16],
    pub user_data: [u8; 20],
}

/// Owned wrapper for QuoteSignatureData
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteSignatureDataWrapper {
    pub isv_signature: Vec<u8>,
    pub attestation_pub_key: Vec<u8>,
    pub qe_report_body: EnclaveReportBody,
    pub qe_report_signature: Vec<u8>,
    pub auth_data: Vec<u8>,
    pub cert_data: QuoteCertDataWrapper,
}

/// Owned wrapper for QuoteCertData
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteCertDataWrapper {
    pub cert_key_type: u16,
    pub cert_data_size: u32,
    pub cert_data: Vec<u8>,
}

/// Convert borrowed Quote to owned QuoteWrapper for serialization
impl<'a> From<&Quote<'a>> for QuoteWrapper {
    fn from(quote: &Quote<'a>) -> Self {
        QuoteWrapper {
            header: QuoteHeaderWrapper {
                version: quote.header.version.get(),
                attestation_key_type: quote.header.attestation_key_type.get(),
                tee_type: quote.header.tee_type,
                qe_svn: quote.header.qe_svn.get(),
                pce_svn: quote.header.pce_svn.get(),
                qe_vendor_id: quote.header.qe_vendor_id,
                user_data: quote.header.user_data,
            },
            body_type: quote.body_type,
            body_size: quote.body_size,
            body: quote.body.clone(),
            signature: QuoteSignatureDataWrapper {
                isv_signature: quote.signature.isv_signature.to_vec(),
                attestation_pub_key: quote.signature.attestation_pub_key.to_vec(),
                qe_report_body: quote.signature.qe_report_body,
                qe_report_signature: quote.signature.qe_report_signature.to_vec(),
                auth_data: quote.signature.auth_data.to_vec(),
                cert_data: QuoteCertDataWrapper {
                    cert_key_type: quote.signature.cert_data.cert_key_type.get(),
                    cert_data_size: quote.signature.cert_data.cert_data_size.get(),
                    cert_data: quote.signature.cert_data.cert_data.to_vec(),
                },
            },
        }
    }
}

// PROBABLY NOT NEEDED NOW - REMOVE LATER IF UNUSED
// impl std::fmt::Display for QuoteWrapper {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         writeln!(f, "Quote:")?;
//         writeln!(f, "  Version: {}", self.header.version)?;
//         writeln!(
//             f,
//             "  TEE Type: 0x{:08x} ({})",
//             self.header.tee_type,
//             match self.header.tee_type {
//                 SGX_TEE_TYPE => "SGX",
//                 TDX_TEE_TYPE => "TDX",
//                 _ => "Unknown",
//             }
//         )?;
//         writeln!(f, "  Body Type: {}", self.body_type)?;
//         writeln!(f, "  Body Size: {} bytes", self.body_size)?;
//         writeln!(f, "  QE SVN: {}", self.header.qe_svn)?;
//         writeln!(f, "  PCE SVN: {}", self.header.pce_svn)?;
//         writeln!(
//             f,
//             "  QE Vendor ID: {}",
//             hex::encode(self.header.qe_vendor_id)
//         )?;

//         match &self.body {
//             QuoteBody::SgxQuoteBody(body) => {
//                 writeln!(f, "  SGX Enclave Report:")?;
//                 writeln!(f, "    MR_ENCLAVE: {}", hex::encode(body.mr_enclave))?;
//                 writeln!(f, "    MR_SIGNER: {}", hex::encode(body.mr_signer))?;
//                 writeln!(f, "    ISV_PROD_ID: {}", body.isv_prod_id)?;
//                 writeln!(f, "    ISV_SVN: {}", body.isv_svn)?;
//                 writeln!(
//                     f,
//                     "    Report Data: {}",
//                     hex::encode(&body.user_report_data)
//                 )?;
//             }
//             QuoteBody::Td10QuoteBody(body) => {
//                 writeln!(f, "  TDX TD10 Report:")?;
//                 writeln!(f, "    TEE_TCB_SVN: {}", hex::encode(body.tee_tcb_svn))?;
//                 writeln!(f, "    MR_SEAM: {}", hex::encode(body.mr_seam))?;
//                 writeln!(f, "    MR_SIGNER_SEAM: {}", hex::encode(body.mr_signer_seam))?;
//                 writeln!(f, "    MR_TD: {}", hex::encode(body.mr_td))?;
//                 writeln!(f, "    RTMR0: {}", hex::encode(body.rtm_r0))?;
//                 writeln!(
//                     f,
//                     "    Report Data: {}",
//                     hex::encode(&body.user_report_data)
//                 )?;
//             }
//             QuoteBody::Td15QuoteBody(body) => {
//                 writeln!(f, "  TDX TD15 Report:")?;
//                 writeln!(f, "    TEE_TCB_SVN: {}", hex::encode(body.td_report.tee_tcb_svn))?;
//                 writeln!(f, "    MR_SEAM: {}", hex::encode(body.td_report.mr_seam))?;
//                 writeln!(f, "    MR_SIGNER_SEAM: {}", hex::encode(body.td_report.mr_signer_seam))?;
//                 writeln!(f, "    MR_TD: {}", hex::encode(body.td_report.mr_td))?;
//                 writeln!(f, "    RTMR0: {}", hex::encode(body.td_report.rtm_r0))?;
//                 writeln!(
//                     f,
//                     "    Report Data: {}",
//                     hex::encode(&body.td_report.user_report_data)
//                 )?;
//                 writeln!(f, "    TEE_TCB_SVN2: {}", hex::encode(body.tee_tcb_svn2))?;
//                 writeln!(f, "    MR_SERVICE_TD: {}", hex::encode(body.mr_service_td))?;
//             }
//         }

//         writeln!(f, "  Signature Data:")?;
//         writeln!(
//             f,
//             "    ISV Signature: {}",
//             hex::encode(&self.signature.isv_signature[..32.min(self.signature.isv_signature.len())])
//         )?;
//         writeln!(
//             f,
//             "    Attestation Public Key: {}",
//             hex::encode(&self.signature.attestation_pub_key[..32.min(self.signature.attestation_pub_key.len())])
//         )?;
//         writeln!(f, "    Auth Data Size: {} bytes", self.signature.auth_data.len())?;
//         writeln!(f, "    Cert Key Type: {}", self.signature.cert_data.cert_key_type)?;
//         writeln!(
//             f,
//             "    Cert Data Size: {} bytes",
//             self.signature.cert_data.cert_data_size
//         )?;

//         Ok(())
//     }
// }
