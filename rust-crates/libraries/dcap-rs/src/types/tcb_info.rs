use std::{str::from_utf8, time::SystemTime};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use p256::ecdsa::VerifyingKey;
use p256::ecdsa::signature::Verifier;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::types::{quote::TDX_TEE_TYPE, report::Td10ReportBody};
use crate::utils::keccak;

use super::{
    quote::{Quote, QuoteBody},
    sgx_x509::SgxPckExtension,
};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TcbInfoAndSignature {
    #[serde(rename = "tcbInfo")]
    pub tcb_info_raw: Box<RawValue>,
    #[serde(with = "hex")]
    pub signature: Vec<u8>,
}

impl TryFrom<String> for TcbInfoAndSignature {
    type Error = serde_json::Error;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        serde_json::from_str(&value)
    }
}

impl TcbInfoAndSignature {
    pub fn as_tcb_info_and_verify(
        &self,
        current_time: SystemTime,
        public_key: VerifyingKey,
    ) -> anyhow::Result<TcbInfo> {
        let tcb_info: TcbInfo =
            serde_json::from_str(self.tcb_info_raw.get()).context("tcb info")?;

        // Make sure current time is between issue_date and next_update
        let current_time: DateTime<Utc> = current_time.into();
        if current_time < tcb_info.issue_date || current_time > tcb_info.next_update {
            bail!("tcb info is not valid at current time");
        }

        let sig = p256::ecdsa::Signature::from_slice(&self.signature).unwrap();
        public_key
            .verify(self.tcb_info_raw.get().as_bytes(), &sig)
            .expect("valid signature expected");

        if tcb_info
            .tcb_levels
            .iter()
            .any(|e| e.tcb.version() != tcb_info.version)
        {
            bail!(
                "mismatched tcb info versions, should all be {:?}",
                tcb_info.version,
            );
        }

        // tcb_type determines how to compare tcb level
        // currently, only 0 is valid
        if tcb_info.tcb_type != 0 {
            bail!("unsupported tcb type {}", tcb_info.tcb_type,);
        }
        Ok(tcb_info)
    }

    pub fn get_tcb_info(&self) -> anyhow::Result<TcbInfo> {
        serde_json::from_slice(self.tcb_info_raw.get().as_bytes())
            .map_err(|e| anyhow::anyhow!("tcb info parsing failed: {}", e))
    }
}

/// Version of the TcbInfo JSON structure
///
/// In the PCS V3 API the TcbInfo version is V2, in the PCS V4 API the TcbInfo
/// version is V3. The V3 API includes advisoryIDs and changes the format of
/// the TcbLevel

#[derive(Deserialize, Serialize, Copy, Clone, Debug, Eq, PartialEq)]
#[serde(try_from = "u32", into = "u32")]
pub enum TcbInfoVersion {
    V2 = 2,
    V3 = 3,
}

impl TryFrom<u32> for TcbInfoVersion {
    type Error = &'static str;
    fn try_from(value: u32) -> std::result::Result<Self, Self::Error> {
        match value {
            2 => Ok(TcbInfoVersion::V2),
            3 => Ok(TcbInfoVersion::V3),
            _ => Err("Unsupported TCB Info version"),
        }
    }
}

impl From<TcbInfoVersion> for u32 {
    fn from(value: TcbInfoVersion) -> Self {
        value as u32
    }
}

#[derive(Debug, Eq, PartialEq, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfo {
    #[serde(skip_serializing_if = "Option::is_none", rename = "id")]
    pub id: Option<String>,
    pub version: TcbInfoVersion,

    pub issue_date: chrono::DateTime<Utc>,

    pub next_update: chrono::DateTime<Utc>,
    pub fmspc: String,
    pub pce_id: String,
    pub tcb_type: u8,
    pub tcb_evaluation_data_number: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tdx_module: Option<TdxModule>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tdx_module_identities: Option<Vec<TdxModuleIdentity>>,
    pub tcb_levels: Vec<TcbLevel>,
}

impl TcbInfo {
    pub fn fmspc_bytes(&self) -> [u8; 6] {
        hex::decode(from_utf8(self.fmspc.as_bytes()).unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    }

    pub fn pce_id_bytes(&self) -> [u8; 2] {
        hex::decode(from_utf8(self.pce_id.as_bytes()).unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    }

    pub fn converge_tcb_status_with_tdx_module(
        platform_status: TcbStatus,
        tdx_module_status: TcbStatus,
    ) -> TcbStatus {
        // Only adjust if TDX module is OutOfDate
        if tdx_module_status != TcbStatus::OutOfDate {
            return platform_status;
        }

        match platform_status {
            TcbStatus::UpToDate | TcbStatus::SWHardeningNeeded => TcbStatus::OutOfDate,

            TcbStatus::ConfigurationNeeded | TcbStatus::ConfigurationAndSWHardeningNeeded => {
                TcbStatus::OutOfDateConfigurationNeeded
            },

            _ => platform_status,
        }
    }
    /// Converge platform TCB status with QE TCB status
    ///
    /// This function implements the rules for combining platform and Quote Enclave TCB
    /// status values, prioritizing the more severe status according to Intel's rules.
    pub fn converge_tcb_status_with_qe_tcb(
        platform_status: TcbStatus,
        qe_status: TcbStatus,
    ) -> TcbStatus {
        // Only adjust status if QE is OutOfDate
        if qe_status != TcbStatus::OutOfDate {
            return platform_status;
        }

        match platform_status {
            // These statuses get overridden to OutOfDate
            TcbStatus::UpToDate | TcbStatus::SWHardeningNeeded => TcbStatus::OutOfDate,

            // These statuses change to reflect both configuration and outdated problems
            TcbStatus::ConfigurationNeeded | TcbStatus::ConfigurationAndSWHardeningNeeded => {
                TcbStatus::OutOfDateConfigurationNeeded
            },

            // All other statuses remain unchanged
            _ => platform_status,
        }
    }

    pub fn get_content_hash(&self) -> Result<[u8; 32]> {
        let id: u8 = match &self.id {
            Some(id) => {
                if id == "SGX" {
                    0
                } else if id == "TDX" {
                    1
                } else {
                    panic!("Unsupported TCB Info ID: {}", id);
                }
            },
            None => 0,
        };

        let mut pre_image: Vec<u8> = vec![];
        pre_image.extend_from_slice(&[self.tcb_type]);
        pre_image.extend_from_slice(&[id]);
        pre_image.extend_from_slice(&u32::from(self.version).to_be_bytes());
        pre_image.extend_from_slice(&self.tcb_evaluation_data_number.to_be_bytes());
        pre_image.extend_from_slice(&self.fmspc_bytes());
        pre_image.extend_from_slice(&self.pce_id_bytes());
        pre_image.extend_from_slice(serde_json::to_vec(&self.tcb_levels)?.as_slice());

        if let Some(tdx_module) = &self.tdx_module {
            pre_image.extend_from_slice(&serde_json::to_vec(tdx_module)?);
        }

        if let Some(tdx_module_identities) = &self.tdx_module_identities {
            pre_image.extend_from_slice(&serde_json::to_vec(tdx_module_identities)?);
        }

        Ok(keccak::hash(&pre_image))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbLevel {
    pub tcb: Tcb,

    pub tcb_date: chrono::DateTime<Utc>,
    pub tcb_status: TcbStatus,
    #[serde(rename = "advisoryIDs", skip_serializing_if = "Option::is_none")]
    pub advisory_ids: Option<Vec<String>>,
}

/// Enum definition as per: <https://github.com/automata-network/automata-on-chain-pccs/blob/d93c4881f1b40930bc72be06008d1e1537004d2f/src/helpers/FmspcTcbHelper.sol#L78-L87>
#[derive(Debug, Eq, PartialEq, Clone, Copy, Deserialize, Serialize)]
#[repr(u8)]
pub enum TcbStatus {
    UpToDate,
    SWHardeningNeeded,
    ConfigurationAndSWHardeningNeeded,
    ConfigurationNeeded,
    OutOfDate,
    OutOfDateConfigurationNeeded,
    Revoked,
    Unspecified,
    RelaunchAdvised,
    RelaunchAdvisedConfigurationNeeded,
}

impl TryFrom<u8> for TcbStatus {
    type Error = &'static str;
    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(TcbStatus::UpToDate),
            1 => Ok(TcbStatus::SWHardeningNeeded),
            2 => Ok(TcbStatus::ConfigurationAndSWHardeningNeeded),
            3 => Ok(TcbStatus::ConfigurationNeeded),
            4 => Ok(TcbStatus::OutOfDate),
            5 => Ok(TcbStatus::OutOfDateConfigurationNeeded),
            6 => Ok(TcbStatus::Revoked),
            7 => Ok(TcbStatus::Unspecified),
            8 => Ok(TcbStatus::RelaunchAdvised),
            9 => Ok(TcbStatus::RelaunchAdvisedConfigurationNeeded),
            _ => Err("Unsupported TCB status"),
        }
    }
}

impl From<TcbStatus> for u8 {
    fn from(value: TcbStatus) -> Self {
        value as u8
    }
}

/// Contains information identifying a TcbLevel.
#[derive(Deserialize, Serialize, PartialEq, Eq, Clone, Debug)]
#[serde(untagged)]
pub enum Tcb {
    V2(TcbV2),
    V3(Box<TcbV3>),
}

impl Tcb {
    fn version(&self) -> TcbInfoVersion {
        match self {
            Tcb::V2(_) => TcbInfoVersion::V2,
            Tcb::V3(_) => TcbInfoVersion::V3,
        }
    }
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Clone, Debug)]
pub struct TcbV3 {
    pub sgxtcbcomponents: [TcbComponentV3; 16],
    pub pcesvn: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tdxtcbcomponents: Option<[TcbComponentV3; 16]>,
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Clone, Debug)]
pub struct TcbComponentV3 {
    pub svn: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "type")]
    pub component_type: Option<String>,
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Clone, Debug)]
pub struct TcbV2 {
    pub sgxtcbcomp01svn: u8,
    pub sgxtcbcomp02svn: u8,
    pub sgxtcbcomp03svn: u8,
    pub sgxtcbcomp04svn: u8,
    pub sgxtcbcomp05svn: u8,
    pub sgxtcbcomp06svn: u8,
    pub sgxtcbcomp07svn: u8,
    pub sgxtcbcomp08svn: u8,
    pub sgxtcbcomp09svn: u8,
    pub sgxtcbcomp10svn: u8,
    pub sgxtcbcomp11svn: u8,
    pub sgxtcbcomp12svn: u8,
    pub sgxtcbcomp13svn: u8,
    pub sgxtcbcomp14svn: u8,
    pub sgxtcbcomp15svn: u8,
    pub sgxtcbcomp16svn: u8,
    pub pcesvn: u16,
}

impl Tcb {
    pub fn pcesvn(&self) -> u16 {
        match self {
            Self::V2(v2) => v2.pcesvn,
            Self::V3(v3) => v3.pcesvn,
        }
    }

    pub fn sgx_tcb_components(&self) -> [u8; 16] {
        match self {
            Self::V2(v2) => [
                v2.sgxtcbcomp01svn,
                v2.sgxtcbcomp02svn,
                v2.sgxtcbcomp03svn,
                v2.sgxtcbcomp04svn,
                v2.sgxtcbcomp05svn,
                v2.sgxtcbcomp06svn,
                v2.sgxtcbcomp07svn,
                v2.sgxtcbcomp08svn,
                v2.sgxtcbcomp09svn,
                v2.sgxtcbcomp10svn,
                v2.sgxtcbcomp11svn,
                v2.sgxtcbcomp12svn,
                v2.sgxtcbcomp13svn,
                v2.sgxtcbcomp14svn,
                v2.sgxtcbcomp15svn,
                v2.sgxtcbcomp16svn,
            ],
            Self::V3(v3) => {
                let mut result = [0u8; 16];
                for (i, comp) in v3.sgxtcbcomponents.iter().enumerate() {
                    result[i] = comp.svn;
                }
                result
            },
        }
    }

    pub fn tdx_tcb_components(&self) -> Option<[u8; 16]> {
        match self {
            Self::V2(_) => None,
            Self::V3(v3) => v3.tdxtcbcomponents.as_ref().map(|components| {
                let mut result = [0u8; 16];
                for i in 0..16 {
                    result[i] = components[i].svn;
                }
                result
            }),
        }
    }
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TdxModule {
    #[serde(rename = "mrsigner")]
    pub mrsigner: String,
    pub attributes: String,
    pub attributes_mask: String,
}

impl TdxModule {
    pub fn mrsigner_bytes(&self) -> [u8; 48] {
        hex::decode(from_utf8(self.mrsigner.as_bytes()).unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    }

    pub fn attributes_bytes(&self) -> [u8; 8] {
        hex::decode(from_utf8(self.attributes.as_bytes()).unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    }

    pub fn attributes_mask_bytes(&self) -> [u8; 8] {
        hex::decode(from_utf8(self.attributes_mask.as_bytes()).unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    }
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TdxModuleIdentity {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "mrsigner")]
    pub mrsigner: String,
    pub attributes: String,
    pub attributes_mask: String,
    pub tcb_levels: Vec<TdxTcbLevel>,
}

impl TdxModuleIdentity {
    pub fn mrsigner_bytes(&self) -> [u8; 48] {
        hex::decode(from_utf8(self.mrsigner.as_bytes()).unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    }

    pub fn attributes_bytes(&self) -> [u8; 8] {
        hex::decode(from_utf8(self.attributes.as_bytes()).unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    }

    pub fn attributes_mask_bytes(&self) -> [u8; 8] {
        hex::decode(from_utf8(self.attributes_mask.as_bytes()).unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    }
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TdxTcbLevel {
    pub tcb: TcbTdx,

    pub tcb_date: chrono::DateTime<Utc>,
    pub tcb_status: TcbStatus,
    #[serde(rename = "advisoryIDs", skip_serializing_if = "Option::is_none")]
    pub advisory_ids: Option<Vec<String>>,
}

impl TdxTcbLevel {
    pub fn in_tcb_level(&self, isv_svn: u8) -> bool {
        self.tcb.isvsvn <= isv_svn
    }
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Clone, Debug)]
pub struct TcbTdx {
    pub isvsvn: u8,
}

impl TcbStatus {
    /// Determine the status of the TCB level that is trustable for the platform
    ///
    /// This function performs TCB (Trusted Computing Base) level verification by:
    /// 1. Finding a matching SGX TCB level based on PCK extension values
    /// 2. Extracting the SGX TCB status and advisories
    /// 3. Checking for TDX TCB status if applicable
    ///
    /// Returns:
    ///   - A tuple containing (sgx_tcb_status, tdx_tcb_status, advisory_ids)
    ///   - sgx_tcb_status: Status of SGX platform components
    ///   - tdx_tcb_status: Status of TDX components (defaults to Unspecified if not applicable)
    ///   - advisory_ids: List of security advisories affecting this TCB level
    pub fn lookup(
        pck_extension: &SgxPckExtension,
        tcb_info: &TcbInfo,
        quote: &Quote,
    ) -> anyhow::Result<(Self, Self, Vec<String>)> {
        // Find first matching TCB level with its index
        let (index, first_matching_level) = tcb_info
            .tcb_levels
            .iter()
            .enumerate()
            .find(|(_, level)| pck_in_tcb_level(level, pck_extension))
            .ok_or_else(|| anyhow::anyhow!("unsupported TCB in pck extension"))?;

        // Extract the SGX TCB status and advisories from the matching level
        let sgx_tcb_status = first_matching_level.tcb_status;
        let mut advisory_ids = first_matching_level
            .advisory_ids
            .clone()
            .unwrap_or_default();

        // Default TDX TCB status to Unspecified
        // Will be updated if a valid TDX module is found in the quote
        let mut tdx_tcb_status = TcbStatus::Unspecified;

        if quote.header.tee_type == TDX_TEE_TYPE {
            let td_report = match &quote.body {
                QuoteBody::Td10QuoteBody(report) => report,
                QuoteBody::Td15QuoteBody(report) => &report.td_report,
                _ => bail!("TDX Quote should only contain Td10 or Td15 report"),
            };

            let matched_tcb_level = match_tdx_tcb(td_report, tcb_info, index)?;
            tdx_tcb_status = matched_tcb_level.tcb_status;
            advisory_ids = matched_tcb_level.advisory_ids.clone().unwrap_or_default();
        }

        // Return the final status determination as a tuple
        Ok((sgx_tcb_status, tdx_tcb_status, advisory_ids))
    }
}

/// Returns true if all the pck components are >= all the tcb level components and
/// the pck pcesvn is >= the tcb level pcesvn.
fn pck_in_tcb_level(level: &TcbLevel, pck_extension: &SgxPckExtension) -> bool {
    const SVN_LENGTH: usize = 16;
    let pck_components: &[u8; SVN_LENGTH] = &pck_extension.tcb.compsvn;

    pck_components
        .iter()
        .zip(level.tcb.sgx_tcb_components())
        .all(|(&pck, tcb)| pck >= tcb)
        && pck_extension.tcb.pcesvn >= level.tcb.pcesvn()
}

fn match_tdx_tcb(
    td_report: &Td10ReportBody,
    tcb_info: &TcbInfo,
    index: usize,
) -> anyhow::Result<TcbLevel> {
    let matching_level: TcbLevel;

    // Start iterating from the found sgx matching level
    for level in &tcb_info.tcb_levels[index..] {
        // Process each level starting from the matching one
        if let Some(tdx_tcb_components) = level.tcb.tdx_tcb_components() {
            let components_match = tdx_tcb_components
                .iter()
                .zip(td_report.tee_tcb_svn.iter())
                .all(|(&comp, &svn)| comp <= svn);

            if components_match {
                // tdx_tcb_status = level.tcb_status;
                // advisory_ids = level.advisory_ids.clone().unwrap_or_default();
                matching_level = level.clone();
                return Ok(matching_level);
            }
        } else {
            // This should not happen, meaning if you have a Td10QuoteBody, you should have a TDX TCB Component present in the TCB Info
            break;
        }
    }

    Err(anyhow::anyhow!(
        "can not find tdx tcb components in tcb info for TDX Quote Body"
    ))
}
