use std::error::Error as StdError;
use std::fmt;
use thiserror::Error;

/// Error type for collateral-related operations.
///
/// This enum represents errors that can occur when fetching or validating
/// attestation collaterals.
#[derive(Debug, Error)]
pub enum CollateralError {
    /// One or more required collaterals are missing or outdated.
    #[error("Missing collaterals")]
    Missing(#[from] MissingCollateralReport),
    /// Quote parsing or validation error.
    #[error("{0}")]
    Validation(String),
}

/// Represents a single missing or outdated collateral item.
///
/// This enum identifies which specific collateral is missing and provides
/// details about what needs to be fetched.
#[derive(Debug, Clone, Error)]
pub enum MissingCollateral {
    /// Missing enclave identity (QE, QVE, or TDQE).
    ///
    /// Contains the identity type and API version.
    #[error("Missing Enclave Identity: {0}, Version: {1}")]
    QEIdentity(String, u32),
    /// Missing TCB info for a specific FMSPC.
    ///
    /// Contains TCB type (0=SGX, 1=TDX), FMSPC hex string, and API version.
    #[error("Missing TCB: {0}, FMSPC: {1}, Version: {2}")]
    FMSPCTCB(u8, String, u32),
    /// Missing PCS certificate or CRL.
    ///
    /// Contains CA name, whether cert is missing, and whether CRL is missing.
    #[error("Missing PCS collateral: CA: {0}, cert missing: {1}, CRL missing: {2}")]
    PCS(String, bool, bool),
}

/// Report containing all missing or outdated collateral items.
///
/// This type aggregates all the collaterals that need to be fetched or updated
/// for successful quote verification.
#[derive(Debug, Clone)]
pub struct MissingCollateralReport {
    missing: Vec<MissingCollateral>,
}

impl MissingCollateralReport {
    /// Creates a new report from a vector of missing collaterals.
    pub fn new(missing: Vec<MissingCollateral>) -> Self {
        Self { missing }
    }

    /// Returns true if there are no missing collaterals.
    pub fn is_empty(&self) -> bool {
        self.missing.is_empty()
    }

    /// Returns the number of missing collaterals.
    pub fn len(&self) -> usize {
        self.missing.len()
    }

    /// Returns a reference to the first missing collateral, if any.
    pub fn first(&self) -> Option<&MissingCollateral> {
        self.missing.first()
    }

    /// Returns an iterator over the missing collaterals.
    pub fn iter(&self) -> impl Iterator<Item = &MissingCollateral> {
        self.missing.iter()
    }

    /// Consumes the report and returns the underlying vector.
    pub fn into_vec(self) -> Vec<MissingCollateral> {
        self.missing
    }

    /// Returns a slice view of the missing collaterals.
    pub fn as_slice(&self) -> &[MissingCollateral] {
        &self.missing
    }
}

impl fmt::Display for MissingCollateralReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.missing.is_empty() {
            write!(f, "All collaterals are present")
        } else {
            writeln!(f, "Missing {} collateral(s):", self.missing.len())?;
            for (i, item) in self.missing.iter().enumerate() {
                writeln!(f, "  {}. {}", i + 1, item)?;
            }
            Ok(())
        }
    }
}

impl StdError for MissingCollateralReport {}

/// Container for all attestation collaterals required for quote verification.
///
/// This struct holds all the certificates, CRLs, TCB info, and enclave identities
/// needed to verify an SGX or TDX quote.
#[derive(Debug, Default)]
pub struct Collaterals {
    /// TCB Info JSON string containing platform TCB levels and status.
    pub tcb_info: String,
    /// QE/TDQE Identity JSON string containing expected enclave measurements.
    pub qe_identity: String,
    /// Intel SGX Root CA certificate in DER format.
    pub root_ca: Vec<u8>,
    /// TCB Signing CA certificate in DER format.
    pub tcb_signing_ca: Vec<u8>,
    /// Root CA Certificate Revocation List in DER format.
    pub root_ca_crl: Vec<u8>,
    /// PCK CA Certificate Revocation List in DER format.
    pub pck_crl: Vec<u8>,
}
