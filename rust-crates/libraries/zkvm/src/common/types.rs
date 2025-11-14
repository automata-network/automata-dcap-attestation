use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Supported zkVM backend types for DCAP attestation verification.
///
/// Each zkVM has its own proving system and guest program implementation.
/// The appropriate zkVM feature must be enabled at compile time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ZkVm {
    /// RISC Zero zkVM backend.
    Risc0,
    /// Succinct SP1 zkVM backend.
    Sp1,
    /// Pico zkVM backend (v1.1+ only).
    Pico,
}

impl ZkVm {
    /// Returns the string representation of this zkVM type.
    pub fn as_str(&self) -> &'static str {
        match self {
            ZkVm::Risc0 => "risc0",
            ZkVm::Sp1 => "sp1",
            ZkVm::Pico => "pico",
        }
    }
}

impl fmt::Display for ZkVm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for ZkVm {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "risc0" => Ok(ZkVm::Risc0),
            "sp1" => Ok(ZkVm::Sp1),
            "pico" => Ok(ZkVm::Pico),
            _ => Err(anyhow::anyhow!("Unsupported zkVM: {}", s)),
        }
    }
}