use zerocopy::AsBytes;

use crate::types::report::{EnclaveReportBody, Td10ReportBody, Td15ReportBody};

use super::{SGX_TEE_TYPE, TDX_TEE_TYPE};

/// Body of the Quote data structure.
#[derive(Debug)]
pub enum QuoteBody {
    SgxQuoteBody(EnclaveReportBody),
    Td10QuoteBody(Td10ReportBody),
    Td15QuoteBody(Td15ReportBody),
}

impl QuoteBody {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::SgxQuoteBody(body) => body.as_bytes(),
            Self::Td10QuoteBody(body) => body.as_bytes(),
            Self::Td15QuoteBody(body) => body.as_bytes(),
        }
    }

    pub fn tee_type(&self) -> u32 {
        match self {
            Self::SgxQuoteBody(_) => SGX_TEE_TYPE,
            Self::Td10QuoteBody(_) => TDX_TEE_TYPE,
            Self::Td15QuoteBody(_) => TDX_TEE_TYPE,
        }
    }

    pub fn as_tdx_report_body(&self) -> Option<&Td10ReportBody> {
        match self {
            Self::Td10QuoteBody(body) => Some(body),
            Self::Td15QuoteBody(body) => Some(&body.td_report),
            _ => None,
        }
    }
}
