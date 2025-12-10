use anyhow::{Context, Result};
use chrono::Utc;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use super::tcb_info::TcbStatus;
use crate::utils::keccak;

const ENCLAVE_IDENTITY_V2: u32 = 2;

#[derive(Default, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QeTcb {
    pub isvsvn: u16,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct QuotingEnclaveIdentityAndSignature {
    #[serde(rename = "enclaveIdentity")]
    pub enclave_identity_raw: Box<RawValue>,
    #[serde(with = "hex")]
    pub signature: Vec<u8>,
}

impl QuotingEnclaveIdentityAndSignature {
    /// Validate the enclave identity and return the enclave identity if it is valid
    /// It checks the signature, the version, and the timestamp.
    /// The enclave identities should have their version set to 2.
    pub fn validate_as_enclave_identity(
        &self,
        public_key: &VerifyingKey,
    ) -> anyhow::Result<EnclaveIdentity> {
        public_key
            .verify(
                self.enclave_identity_raw.to_string().as_bytes(),
                &Signature::from_slice(&self.signature)?,
            )
            .context("Failed to verify enclave identity signature")?;

        let enclave_identity: EnclaveIdentity =
            serde_json::from_str(self.enclave_identity_raw.get())
                .context("Failed to deserialize enclave identity")?;

        if enclave_identity.version != ENCLAVE_IDENTITY_V2 {
            return Err(anyhow::anyhow!(
                "unsupported enclave identity version, only v2 is supported"
            ));
        }

        Ok(enclave_identity)
    }

    pub fn get_enclave_identity_bytes(&self) -> Vec<u8> {
        self.enclave_identity_raw.to_string().into_bytes()
    }

    pub fn get_enclave_identity(&self) -> anyhow::Result<EnclaveIdentity> {
        serde_json::from_str(self.enclave_identity_raw.get())
            .context("Failed to deserialize enclave identity")
    }

    pub fn get_signature_bytes(&self) -> Vec<u8> {
        self.signature.clone()
    }
}

#[derive(Deserialize, Serialize, Debug, Clone, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EnclaveIdentity {
    /// Identifier of the SGX Enclave issued by Intel.
    pub id: EnclaveType,

    /// Version of the structure.
    pub version: u32,

    /// The time the Enclave Identity Information was created. The time shalle be in UTC
    /// and the encoding shall be compliant to ISO 8601 standard (YYYY-MM-DDhh:mm:ssZ)
    pub issue_date: chrono::DateTime<Utc>,

    /// The time by which next Enclave Identity information will be issued. The time shall be in UTC
    /// and the encoding shall be compliant to ISO 8601 standard (YYYY-MM-DDhh:mm:ssZ)
    pub next_update: chrono::DateTime<Utc>,

    /// A monotonically increasing sequence number changed when Intel updates the content of the TCB evaluation data set:
    /// TCB Info, QE Identity, QVE Identity. The tcbEvaluationDataNUmber update is synchronized across TCB infor for all
    /// flavours of SGX CPUs (Family-Model-Stepping-Platform-CustomSKU) and QE/QVE Identity.
    /// This sequence number allows users to easily determine when a particular TCB Info/QE Identity/QVE Identity
    /// superseedes another TCB Info/QE Identity/QVE Identity (value: current TCB Recovery event number stored in the database).
    pub tcb_evaluation_data_number: u32,

    /// Base 16-encoded string representing miscselect "golden" value (upon applying mask).
    pub miscselect: String,

    /// Base 16-encoded string representing mask to be applied to miscselect value retrieved from the platform.
    pub miscselect_mask: String,

    /// Base 16-encoded string representing attributes "golden" value (upon applying mask).
    pub attributes: String,

    /// Base 16-encoded string representing mask to be applied to attributes value retrieved from the platform.
    pub attributes_mask: String,

    /// Base 16-encoded string representing mrsigner hash.
    pub mrsigner: String,

    /// Enclave Product ID.
    pub isvprodid: u16,

    /// Sorted list of supported Enclave TCB levels for given QVE encoded as a JSON array of Enclave TCB level objects.
    pub tcb_levels: Vec<QeTcbLevel>,
}

impl EnclaveIdentity {
    pub fn miscselect_bytes(&self) -> [u8; 4] {
        hex::decode(&self.miscselect)
            .expect("Failed to decode miscselect")
            .try_into()
            .expect("miscselect should be 4 bytes")
    }

    pub fn miscselect_mask_bytes(&self) -> [u8; 4] {
        hex::decode(&self.miscselect_mask)
            .expect("Failed to decode miscselect mask")
            .try_into()
            .expect("miscselect mask should be 4 bytes")
    }

    pub fn attributes_bytes(&self) -> [u8; 16] {
        hex::decode(&self.attributes)
            .expect("Failed to decode attributes")
            .try_into()
            .expect("attributes should be 16 bytes")
    }

    pub fn attributes_mask_bytes(&self) -> [u8; 16] {
        hex::decode(&self.attributes_mask)
            .expect("Failed to decode attributes mask")
            .try_into()
            .expect("attributes mask should be 16 bytes")
    }

    pub fn mrsigner_bytes(&self) -> [u8; 32] {
        hex::decode(&self.mrsigner)
            .expect("Failed to decode mrsigner")
            .try_into()
            .expect("mrsigner should be 32 bytes")
    }

    pub fn get_qe_tcb_status(&self, isv_svn: u16) -> QeTcbStatus {
        self.tcb_levels
            .iter()
            .find(|level| level.tcb.isvsvn <= isv_svn)
            .map(|level| level.tcb_status)
            .unwrap_or(QeTcbStatus::Unspecified)
    }

    pub fn get_content_hash(&self) -> Result<[u8; 32]> {
        let mut pre_image: Vec<u8> = vec![];
        pre_image.extend_from_slice(&[u8::from(self.id)]);
        pre_image.extend_from_slice(&self.version.to_be_bytes());
        pre_image.extend_from_slice(&self.tcb_evaluation_data_number.to_be_bytes());
        pre_image.extend_from_slice(&self.miscselect_bytes());
        pre_image.extend_from_slice(&self.miscselect_mask_bytes());
        pre_image.extend_from_slice(&self.attributes_bytes());
        pre_image.extend_from_slice(&self.attributes_mask_bytes());
        pre_image.extend_from_slice(&self.mrsigner_bytes());
        pre_image.extend_from_slice(&self.isvprodid.to_be_bytes());
        pre_image.extend_from_slice(serde_json::to_vec(&self.tcb_levels)?.as_slice());
        Ok(keccak::hash(&pre_image))
    }
}

/// Enclave TCB level
#[derive(Deserialize, Serialize, Debug, Clone, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct QeTcbLevel {
    /// SGX Enclave's ISV SVN
    pub tcb: QeTcb,
    /// The time the TCB was evaluated. The time shall be in UTC and the encoding shall be compliant to ISO 8601 standard (YYYY-MM-DDhh:mm:ssZ)
    pub tcb_date: chrono::DateTime<Utc>,
    /// TCB level status
    pub tcb_status: QeTcbStatus,
    #[serde(rename = "advisoryIDs")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advisory_ids: Option<Vec<String>>,
}

/// TCB level status
#[derive(Deserialize, Serialize, Debug, Clone, Copy, Eq, PartialEq)]
#[repr(u8)]
pub enum QeTcbStatus {
    UpToDate,
    SWHardeningNeeded,
    ConfigurationAndSWHardeningNeeded,
    ConfigurationNeeded,
    OutOfDate,
    OutOfDateConfigurationNeeded,
    Revoked,
    Unspecified,
}

impl std::fmt::Display for QeTcbStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QeTcbStatus::UpToDate => write!(f, "UpToDate"),
            QeTcbStatus::OutOfDate => write!(f, "OutOfDate"),
            QeTcbStatus::Revoked => write!(f, "Revoked"),
            QeTcbStatus::ConfigurationNeeded => write!(f, "ConfigurationNeeded"),
            QeTcbStatus::ConfigurationAndSWHardeningNeeded => {
                write!(f, "ConfigurationAndSWHardeningNeeded")
            },
            QeTcbStatus::SWHardeningNeeded => write!(f, "SWHardeningNeeded"),
            QeTcbStatus::OutOfDateConfigurationNeeded => write!(f, "OutOfDateConfigurationNeeded"),
            QeTcbStatus::Unspecified => write!(f, "Unspecified"),
        }
    }
}

impl TryFrom<u8> for QeTcbStatus {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(QeTcbStatus::UpToDate),
            1 => Ok(QeTcbStatus::SWHardeningNeeded),
            2 => Ok(QeTcbStatus::OutOfDate),
            3 => Ok(QeTcbStatus::OutOfDateConfigurationNeeded),
            4 => Ok(QeTcbStatus::ConfigurationNeeded),
            5 => Ok(QeTcbStatus::ConfigurationAndSWHardeningNeeded),
            6 => Ok(QeTcbStatus::Revoked),
            _ => Err("Invalid TCB status"),
        }
    }
}

impl From<QeTcbStatus> for u8 {
    fn from(value: QeTcbStatus) -> Self {
        match value {
            QeTcbStatus::UpToDate => 0,
            QeTcbStatus::SWHardeningNeeded => 1,
            QeTcbStatus::OutOfDate => 2,
            QeTcbStatus::OutOfDateConfigurationNeeded => 3,
            QeTcbStatus::ConfigurationNeeded => 4,
            QeTcbStatus::ConfigurationAndSWHardeningNeeded => 5,
            QeTcbStatus::Revoked => 6,
            QeTcbStatus::Unspecified => 7,
        }
    }
}

#[allow(clippy::from_over_into)]
impl Into<TcbStatus> for QeTcbStatus {
    fn into(self) -> TcbStatus {
        match self {
            QeTcbStatus::UpToDate => TcbStatus::UpToDate,
            QeTcbStatus::OutOfDate => TcbStatus::OutOfDate,
            QeTcbStatus::Revoked => TcbStatus::Revoked,
            QeTcbStatus::ConfigurationNeeded => TcbStatus::ConfigurationNeeded,
            QeTcbStatus::ConfigurationAndSWHardeningNeeded => {
                TcbStatus::ConfigurationAndSWHardeningNeeded
            },
            QeTcbStatus::SWHardeningNeeded => TcbStatus::SWHardeningNeeded,
            QeTcbStatus::OutOfDateConfigurationNeeded => TcbStatus::OutOfDateConfigurationNeeded,
            QeTcbStatus::Unspecified => TcbStatus::Unspecified,
        }
    }
}

impl std::str::FromStr for QeTcbStatus {
    type Err = anyhow::Error;

    fn from_str(status: &str) -> Result<Self, Self::Err> {
        match status {
            "UpToDate" => Ok(QeTcbStatus::UpToDate),
            "OutOfDate" => Ok(QeTcbStatus::OutOfDate),
            "Revoked" => Ok(QeTcbStatus::Revoked),
            _ => Ok(QeTcbStatus::Unspecified),
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
#[repr(u8)]
pub enum EnclaveType {
    /// Quoting Enclave
    Qe = 0,
    /// Quote Verification Enclave
    Qve = 1,
    /// TDX Quoting Enclave
    #[serde(rename = "TD_QE")]
    TdQe = 2,
}

impl TryFrom<u8> for EnclaveType {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(EnclaveType::Qe),
            1 => Ok(EnclaveType::Qve),
            2 => Ok(EnclaveType::TdQe),
            _ => Err("Invalid enclave type"),
        }
    }
}

impl From<EnclaveType> for u8 {
    fn from(enclave_type: EnclaveType) -> Self {
        match enclave_type {
            EnclaveType::Qe => 0,
            EnclaveType::Qve => 1,
            EnclaveType::TdQe => 2,
        }
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use sha2::{Digest, Sha256};

//     #[test]
//     fn test_enclave_identity_serialization() {
//         let qe_identity = include_bytes!("../../data/qeidentityv2_apiv4.json");
//         let qe_identity: QuotingEnclaveIdentityAndSignature =
//             serde_json::from_slice(qe_identity).unwrap();
//         let qe_identity_parsed = qe_identity.get_enclave_identity().unwrap();

//         let original_qe_identity_hash =
//             Sha256::digest(qe_identity.enclave_identity_raw.get().as_bytes());

//         let serialized_qe_identity = serde_json::to_string(&qe_identity_parsed).unwrap();
//         let serialized_qe_identity_hash = Sha256::digest(serialized_qe_identity.as_bytes());

//         assert_eq!(original_qe_identity_hash, serialized_qe_identity_hash);
//     }
// }
