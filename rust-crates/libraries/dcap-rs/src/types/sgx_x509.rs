//! SGX X.509 Certificate Extension Parser
//!
//! This module provides functionality to parse Intel SGX-specific extensions
//! from X.509 certificates, particularly PCK (Platform Certificate Key) certificates.
//!
//! # Overview
//! Intel SGX attestation relies on certificates that contain custom extensions
//! with information about platform security versions, identity, and configuration.
//! This module defines structures and parsing logic for these SGX-specific extensions.
//!
//! # Main Components
//! - `SgxPckExtension`: Main structure containing parsed SGX extension data
//! - OID constants: Defines Object Identifiers for SGX extensions
//! - Parsing logic: Functions to extract and validate extension data
//! - Type conversion: Traits to convert ASN.1 encoded values to Rust types

use std::collections::HashMap;

use anyhow::{Context, Error, Result, anyhow};
use asn1::{ObjectIdentifier, SequenceOf, oid};

/// Intel SGX Extensions OID root
/// Identifies the root OID for all SGX extensions (1.2.840.113741.1.13.1)
pub const SGX_EXTENSIONS_OID: &str = "1.2.840.113741.1.13.1";
const _SGX_EXTENSIONS_OID_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1);

/// Platform Provisioning ID (PPID) OID
/// Uniquely identifies an SGX-enabled platform
const PPID_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 1);

/// TCB (Trusted Computing Base) Information OID
/// Contains security version numbers for platform components
const TCB_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2);

/// TCB Component SVN (Security Version Numbers) OIDs
/// Each component has its own security version number
const TCB_COMP01SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 1);
const TCB_COMP02SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 2);
const TCB_COMP03SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 3);
const TCB_COMP04SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 4);
const TCB_COMP05SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 5);
const TCB_COMP06SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 6);
const TCB_COMP07SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 7);
const TCB_COMP08SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 8);
const TCB_COMP09SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 9);
const TCB_COMP10SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 10);
const TCB_COMP11SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 11);
const TCB_COMP12SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 12);
const TCB_COMP13SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 13);
const TCB_COMP14SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 14);
const TCB_COMP15SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 15);
const TCB_COMP16SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 16);
const TCB_PCESVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 17);
const TCB_CPUSVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 18);

/// PCE ID (Platform Certificate Enclave ID) OID
/// Identifies the specific PCE instance
const PCE_ID_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 3);

/// FMSPC (Family-Model-Stepping-Platform-CustomSKU) OID
/// Platform identifier used for TCB tracking
const FMSPC_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 4);

/// SGX Type OID
/// Indicates whether platform is standard or scalable
const SGX_TYPE_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 5);

/// Platform Instance ID OID
/// Unique identifier for the specific platform instance
const PLATFORM_INSTANCE_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 6);

/// Configuration OID
/// Contains platform configuration information
const CONFIGURATION_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 7);
const CONFIGURATION_DYNAMIC_PLATFORM_OID: ObjectIdentifier =
    oid!(1, 2, 840, 113741, 1, 13, 1, 7, 1);
const CONFIGURATION_CACHED_KEYS_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 7, 2);
const CONFIGURATION_SMT_ENABLED_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 7, 3);

/// Field size constants for binary data
const PPID_LEN: usize = 16;
const CPUSVN_LEN: usize = 16;
const PCEID_LEN: usize = 2;
const FMSPC_LEN: usize = 6;
const PLATFORM_INSTANCE_ID_LEN: usize = 16;
const COMPSVN_LEN: usize = 16;

/// Main structure containing parsed SGX PCK extension data
///
/// This structure stores all the SGX-specific information extracted from
/// a PCK certificate's extensions, including platform identity, TCB levels,
/// and configuration information.
#[derive(Debug, Clone)]
pub struct SgxPckExtension {
    pub ppid: [u8; PPID_LEN],

    /// TCB Information - Contains security version numbers for platform components
    pub tcb: Tcb,

    /// PCE ID - Identifies the Platform Certificate Enclave instance
    pub pceid: [u8; PCEID_LEN],

    /// FMSPC - Family-Model-Stepping-Platform-CustomSKU identifier
    pub fmspc: [u8; FMSPC_LEN],
    _sgx_type: SgxType,
    _platform_instance_id: Option<[u8; PLATFORM_INSTANCE_ID_LEN]>,
    _configuration: Option<Configuration>,
}

impl SgxPckExtension {
    pub fn is_pck_ext(oid: String) -> bool {
        oid == SGX_EXTENSIONS_OID
    }

    pub fn from_der(der: &[u8]) -> Result<Self> {
        let mut ppid = None;
        let mut tcb = None;
        let mut pceid = None;
        let mut fmspc = None;
        let mut sgx_type = None;
        let mut platform_instance_id: Option<[u8; PLATFORM_INSTANCE_ID_LEN]> = None;
        let mut configuration: Option<Configuration> = None;

        let extensions = asn1::parse_single::<SequenceOf<SgxExtension>>(der)
            .map_err(|_| anyhow!("malformed PCK certificate"))?;

        parse_extensions(
            extensions,
            HashMap::from([
                (
                    PPID_OID,
                    &mut ppid as &mut dyn OptionOfTryFromExtensionValue,
                ),
                (TCB_OID, &mut tcb),
                (PCE_ID_OID, &mut pceid),
                (FMSPC_OID, &mut fmspc),
                (SGX_TYPE_OID, &mut sgx_type),
                (PLATFORM_INSTANCE_OID, &mut platform_instance_id),
                (CONFIGURATION_OID, &mut configuration),
            ]),
        )?;

        Ok(Self {
            ppid: ppid.unwrap(),
            tcb: tcb.unwrap(),
            pceid: pceid.unwrap(),
            fmspc: fmspc.unwrap(),
            _sgx_type: sgx_type.unwrap(),
            _platform_instance_id: platform_instance_id,
            _configuration: configuration,
        })
    }
}

#[derive(asn1::Asn1Read, Debug)]
struct SgxExtension<'a> {
    pub sgx_extension_id: ObjectIdentifier,
    pub value: ExtensionValue<'a>,
}

#[derive(asn1::Asn1Read)]
enum ExtensionValue<'a> {
    OctetString(&'a [u8]),
    Sequence(SequenceOf<'a, SgxExtension<'a>>),
    Integer(u64),
    Enumerated(asn1::Enumerated),
    Bool(bool),
}

impl std::fmt::Debug for ExtensionValue<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExtensionValue::OctetString(s) => write!(f, "octet string: {:?}", s),
            ExtensionValue::Sequence(_) => write!(f, "sequence"),
            ExtensionValue::Integer(i) => write!(f, "integer: {:?}", i),
            ExtensionValue::Enumerated(e) => write!(f, "enumerated: {:?}", e),
            ExtensionValue::Bool(b) => write!(f, "bool: {:?}", b),
        }
    }
}

impl<'a> TryFrom<ExtensionValue<'a>> for u8 {
    type Error = Error;

    fn try_from(value: ExtensionValue<'a>) -> Result<Self, Self::Error> {
        if let ExtensionValue::Integer(i) = value {
            i.try_into()
                .map_err(|_| anyhow!("malformed extension value in PCK certificate"))
        } else {
            Err(anyhow!("expected integer value"))
        }
    }
}

impl<'a> TryFrom<ExtensionValue<'a>> for u16 {
    type Error = Error;

    fn try_from(value: ExtensionValue<'a>) -> Result<Self, Self::Error> {
        if let ExtensionValue::Integer(i) = value {
            i.try_into()
                .map_err(|_| anyhow!("malformed extension value in PCK certificate"))
        } else {
            Err(anyhow!("expected integer value"))
        }
    }
}

impl<'a, const LEN: usize> TryFrom<ExtensionValue<'a>> for [u8; LEN] {
    type Error = Error;

    fn try_from(value: ExtensionValue<'a>) -> Result<Self, Self::Error> {
        if let ExtensionValue::OctetString(s) = value {
            s.try_into()
                .map_err(|_| anyhow!("malformed extension value in PCK certificate"))
        } else {
            Err(anyhow!("expected octet string value"))
        }
    }
}

impl<'a> TryFrom<ExtensionValue<'a>> for bool {
    type Error = Error;

    fn try_from(value: ExtensionValue<'a>) -> Result<Self, Self::Error> {
        if let ExtensionValue::Bool(b) = value {
            Ok(b)
        } else {
            Err(anyhow!("expected boolean value"))
        }
    }
}

#[derive(Debug, Clone)]
pub struct Tcb {
    pub compsvn: [u8; COMPSVN_LEN],
    pub pcesvn: u16,
    pub cpusvn: [u8; CPUSVN_LEN],
}

impl<'a> TryFrom<ExtensionValue<'a>> for Tcb {
    type Error = Error;

    fn try_from(value: ExtensionValue<'a>) -> Result<Self, Self::Error> {
        if let ExtensionValue::Sequence(seq) = value {
            Self::try_from(seq)
        } else {
            Err(anyhow!("malformed extension value in PCK certificate"))
        }
    }
}

impl<'a> TryFrom<SequenceOf<'a, SgxExtension<'a>>> for Tcb {
    type Error = Error;

    fn try_from(value: SequenceOf<'a, SgxExtension<'a>>) -> Result<Self, Self::Error> {
        let mut compsvn = [None; COMPSVN_LEN];
        let mut pcesvn = None;
        let mut cpusvn = None;

        let [
            compsvn01,
            compsvn02,
            compsvn03,
            compsvn04,
            compsvn05,
            compsvn06,
            compsvn07,
            compsvn08,
            compsvn09,
            compsvn10,
            compsvn11,
            compsvn12,
            compsvn13,
            compsvn14,
            compsvn15,
            compsvn16,
        ] = &mut compsvn;

        parse_extensions(
            value,
            HashMap::from([
                (
                    TCB_COMP01SVN_OID,
                    compsvn01 as &mut dyn OptionOfTryFromExtensionValue,
                ),
                (TCB_COMP02SVN_OID, compsvn02),
                (TCB_COMP03SVN_OID, compsvn03),
                (TCB_COMP04SVN_OID, compsvn04),
                (TCB_COMP05SVN_OID, compsvn05),
                (TCB_COMP06SVN_OID, compsvn06),
                (TCB_COMP07SVN_OID, compsvn07),
                (TCB_COMP08SVN_OID, compsvn08),
                (TCB_COMP09SVN_OID, compsvn09),
                (TCB_COMP10SVN_OID, compsvn10),
                (TCB_COMP11SVN_OID, compsvn11),
                (TCB_COMP12SVN_OID, compsvn12),
                (TCB_COMP13SVN_OID, compsvn13),
                (TCB_COMP14SVN_OID, compsvn14),
                (TCB_COMP15SVN_OID, compsvn15),
                (TCB_COMP16SVN_OID, compsvn16),
                (TCB_PCESVN_OID, &mut pcesvn),
                (TCB_CPUSVN_OID, &mut cpusvn),
            ]),
        )?;

        Ok(Self {
            compsvn: compsvn.map(Option::unwrap),
            pcesvn: pcesvn.unwrap(),
            cpusvn: cpusvn.unwrap(),
        })
    }
}

// This trait exists to allow storing different Option<T> types in the same HashMap
// (where each T has its own TryFrom<ExtensionValue> implementation).
// It solves the problem of heterogeneous types in the same HashMap.
// TODO(udit): Need to find a better way to do this
trait OptionOfTryFromExtensionValue {
    // Convert ExtensionValue to the appropriate type and store it
    fn parse_and_save(&mut self, value: ExtensionValue<'_>) -> Result<()>;
    // Check if value is missing
    fn is_none(&self) -> bool;
}

impl<T> OptionOfTryFromExtensionValue for Option<T>
where
    T: for<'a> TryFrom<ExtensionValue<'a>, Error = Error>,
{
    fn parse_and_save(&mut self, value: ExtensionValue<'_>) -> Result<()> {
        if self.is_some() {
            return Err(anyhow!("duplicate extension in PCK certificate"));
        }
        *self = Some(T::try_from(value)?);
        Ok(())
    }

    fn is_none(&self) -> bool {
        self.is_none()
    }
}

fn parse_extensions<'a>(
    extensions: asn1::SequenceOf<'a, SgxExtension<'a>>,
    mut attributes: HashMap<ObjectIdentifier, &mut dyn OptionOfTryFromExtensionValue>,
) -> Result<()> {
    for extension in extensions {
        let SgxExtension {
            sgx_extension_id,
            value,
        } = extension;

        if let Some(attr) = attributes.get_mut(&sgx_extension_id) {
            attr.parse_and_save(value)
                .with_context(|| sgx_extension_id.to_string())?;
        } else {
            return Err(anyhow!(
                "unknown extension in PCK certificate: {:?}",
                sgx_extension_id
            ));
        }
    }

    for (oid, attr) in attributes {
        // It seems that the platform instance id and configuration are optional in the
        // PCK certificate. TODO(udit): Confirm this. For time, being this is hardcoded,
        // to avoid panics, we ignore these two extensions.
        if attr.is_none() && oid != PLATFORM_INSTANCE_OID && oid != CONFIGURATION_OID {
            return Err(anyhow!("missing extension in PCK certificate: {:?}", oid));
        }
    }

    Ok(())
}

#[derive(Debug, Clone)]
pub(crate) enum SgxType {
    Standard,
    Scalable,
}

impl<'a> TryFrom<ExtensionValue<'a>> for SgxType {
    type Error = Error;
    fn try_from(value: ExtensionValue<'a>) -> Result<Self> {
        if let ExtensionValue::Enumerated(v) = value {
            Self::try_from(v)
        } else {
            Err(anyhow!("malformed extension value in PCK certificate"))
        }
    }
}

impl TryFrom<asn1::Enumerated> for SgxType {
    type Error = Error;
    fn try_from(value: asn1::Enumerated) -> Result<Self> {
        match value.value() {
            0 => Ok(SgxType::Standard),
            1 => Ok(SgxType::Scalable),
            _ => Err(anyhow!("unknown SGX type in PCK certificate")),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Configuration {
    // TODO should we let clients specify configuration requirements?
    //   e.g. disallow `smt_enabled = true`
    _dynamic_platform: bool,
    _cached_keys: bool,
    _smt_enabled: bool,
}

impl<'a> TryFrom<ExtensionValue<'a>> for Configuration {
    type Error = Error;

    fn try_from(value: ExtensionValue<'a>) -> Result<Self> {
        if let ExtensionValue::Sequence(v) = value {
            Self::try_from(v)
        } else {
            Err(anyhow!("malformed extension value in PCK certificate"))
        }
    }
}

impl<'a> TryFrom<SequenceOf<'a, SgxExtension<'a>>> for Configuration {
    type Error = Error;

    fn try_from(value: SequenceOf<'a, SgxExtension<'a>>) -> Result<Self> {
        let mut dynamic_platform = None;
        let mut cached_keys = None;
        let mut smt_enabled = None;

        parse_extensions(
            value,
            HashMap::from([
                (
                    CONFIGURATION_DYNAMIC_PLATFORM_OID,
                    &mut dynamic_platform as &mut dyn OptionOfTryFromExtensionValue,
                ),
                (CONFIGURATION_CACHED_KEYS_OID, &mut cached_keys),
                (CONFIGURATION_SMT_ENABLED_OID, &mut smt_enabled),
            ]),
        )?;

        Ok(Self {
            _dynamic_platform: dynamic_platform.unwrap(),
            _cached_keys: cached_keys.unwrap(),
            _smt_enabled: smt_enabled.unwrap(),
        })
    }
}

// #[cfg(test)]
// mod test {
//     use super::*;

//     #[test]
//     fn test_deserialization() {
//         const DATA: &[u8] = include_bytes!("../../data/sgx_x509_extension.der");

//         let ext = SgxPckExtension::from_der(DATA).unwrap();

//         assert_eq!(ext.pceid, [0u8, 0u8]);
//         assert_eq!(ext.tcb.pcesvn, 11);
//         assert_eq!(ext.tcb.compsvn[0], 4);
//     }
// }
