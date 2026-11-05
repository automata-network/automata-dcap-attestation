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
/// Indicates standard, scalable, or scalable-with-integrity platforms
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
    pub fn platform_instance_id(&self) -> Option<[u8; PLATFORM_INSTANCE_ID_LEN]> {
        self._platform_instance_id
    }

    /// Presence, independent of the three configuration flag values.
    pub(crate) fn configuration_present(&self) -> bool {
        self._configuration.is_some()
    }

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
            ppid: ppid.context("missing PPID extension in PCK certificate")?,
            tcb: tcb.context("missing TCB extension in PCK certificate")?,
            pceid: pceid.context("missing PCE ID extension in PCK certificate")?,
            fmspc: fmspc.context("missing FMSPC extension in PCK certificate")?,
            _sgx_type: sgx_type.context("missing SGX type extension in PCK certificate")?,
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

        let compsvn = compsvn
            .into_iter()
            .enumerate()
            .map(|(index, value)| {
                value.ok_or_else(|| {
                    anyhow!(
                        "missing TCB component {} SVN extension in PCK certificate",
                        index + 1
                    )
                })
            })
            .collect::<Result<Vec<_>>>()?
            .try_into()
            .map_err(|_| anyhow!("PCK certificate must contain 16 TCB component SVN values"))?;

        Ok(Self {
            compsvn,
            pcesvn: pcesvn.context("missing PCE SVN extension in PCK certificate")?,
            cpusvn: cpusvn.context("missing CPU SVN extension in PCK certificate")?,
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
        // Intel PCK Certificate Profile 1.5 makes these fields issuer-dependent.
        // V2 checks their presence after authenticating the certificate chain.
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
    // Intel PCK Certificate and CRL Profile Specification 1.5, SGX Type (OID .1.5).
    ScalableWithIntegrity,
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
            2 => Ok(SgxType::ScalableWithIntegrity),
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
            _dynamic_platform: dynamic_platform
                .context("missing dynamic platform configuration in PCK certificate")?,
            _cached_keys: cached_keys
                .context("missing cached keys configuration in PCK certificate")?,
            _smt_enabled: smt_enabled.context("missing SMT configuration in PCK certificate")?,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::quote::Quote;

    fn fixture_extension() -> Vec<u8> {
        let bytes = hex::decode(include_str!("../../../../samples/quotev4.hex").trim()).unwrap();
        let quote = Quote::read(&mut bytes.as_slice()).unwrap();
        let chain = quote.signature.get_pck_cert_chain().unwrap();
        chain.pck_cert_chain[0]
            .tbs_certificate
            .extensions
            .as_ref()
            .unwrap()
            .iter()
            .find(|extension| extension.extn_id.to_string() == SGX_EXTENSIONS_OID)
            .unwrap()
            .extn_value
            .as_bytes()
            .to_vec()
    }

    fn sgx_type_value_offset(der: &[u8]) -> usize {
        // SGX Type OID followed by ASN.1 ENUMERATED and its one-byte length.
        let prefix = hex::decode("060a2a864886f84d010d01050a01").unwrap();
        let offsets: Vec<_> = der
            .windows(prefix.len())
            .enumerate()
            .filter_map(|(i, value)| (value == prefix).then_some(i + prefix.len()))
            .collect();
        assert_eq!(offsets.len(), 1);
        offsets[0]
    }

    #[test]
    fn pck_extension_accepts_scalable_with_integrity_without_changing_tcb() {
        let mut der = fixture_extension();
        let original = SgxPckExtension::from_der(&der).unwrap();
        let offset = sgx_type_value_offset(&der);
        der[offset] = 2;
        let parsed = SgxPckExtension::from_der(&der).unwrap();
        assert!(matches!(parsed._sgx_type, SgxType::ScalableWithIntegrity));
        assert_eq!(parsed.tcb.compsvn, original.tcb.compsvn);
        assert_eq!(parsed.tcb.pcesvn, original.tcb.pcesvn);
        assert_eq!(parsed.tcb.cpusvn, original.tcb.cpusvn);
        assert_eq!(parsed.fmspc, original.fmspc);
        assert_eq!(parsed.pceid, original.pceid);
        assert_eq!(
            parsed.platform_instance_id(),
            original.platform_instance_id()
        );
        // Only extension parsing is tested here. Modifying a signed certificate
        // does not make its signature valid.
    }

    fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut encoded = vec![tag];
        if value.len() < 128 {
            encoded.push(value.len() as u8);
        } else if value.len() < 256 {
            encoded.extend([0x81, value.len() as u8]);
        } else {
            encoded.push(0x82);
            encoded.extend(u16::try_from(value.len()).unwrap().to_be_bytes());
        }
        encoded.extend(value);
        encoded
    }

    fn field(prefix: &[u8], id: u8, value: &[u8]) -> Vec<u8> {
        let mut oid = prefix.to_vec();
        oid.push(id);
        tlv(0x30, &[tlv(0x06, &oid), value.to_vec()].concat())
    }

    fn with_profile(sgx_type: u8, piid: bool, configuration: Option<&[u8]>) -> Vec<u8> {
        let der = fixture_extension();
        let mut fields = Vec::new();
        for raw in asn1::parse_single::<SequenceOf<asn1::Tlv<'_>>>(&der).unwrap() {
            let ext = asn1::parse_single::<SgxExtension<'_>>(raw.full_data()).unwrap();
            if ext.sgx_extension_id != PLATFORM_INSTANCE_OID
                && ext.sgx_extension_id != CONFIGURATION_OID
            {
                fields.extend(raw.full_data());
            }
        }
        let prefix = hex::decode("2a864886f84d010d01").unwrap();
        if piid {
            fields.extend(field(&prefix, 6, &tlv(0x04, &[0; 16])));
        }
        if let Some(config) = configuration {
            fields.extend(field(&prefix, 7, config));
        }
        let mut result = tlv(0x30, &fields);
        let offset = sgx_type_value_offset(&result);
        result[offset] = sgx_type;
        result
    }

    fn configuration_fields() -> [Vec<u8>; 3] {
        let prefix = hex::decode("2a864886f84d010d0107").unwrap();
        [1, 2, 3].map(|id| field(&prefix, id, &[0x01, 0x01, 0x00]))
    }

    #[test]
    fn configuration_presence_is_independent_of_flag_values() {
        let config = tlv(0x30, &configuration_fields().concat());
        for sgx_type in 0..=2 {
            for piid in [false, true] {
                for present in [false, true] {
                    let der = with_profile(sgx_type, piid, present.then_some(config.as_slice()));
                    let parsed = SgxPckExtension::from_der(&der).unwrap();
                    assert_eq!(parsed.platform_instance_id().is_some(), piid);
                    assert_eq!(parsed.configuration_present(), present);
                    if let Some(flags) = parsed._configuration {
                        assert!(
                            !flags._dynamic_platform && !flags._cached_keys && !flags._smt_enabled
                        );
                    }
                    // Issuer-dependent validation follows authentication in v2, not raw parsing.
                }
            }
        }
    }

    #[test]
    fn rejects_malformed_configuration_with_piid_present() {
        let [first, second, third] = configuration_fields();
        let prefix = hex::decode("2a864886f84d010d0107").unwrap();
        let invalid = [
            tlv(0x30, &[]),
            tlv(0x30, &[first.clone(), second.clone()].concat()),
            tlv(
                0x30,
                &[first.clone(), second.clone(), third.clone(), third.clone()].concat(),
            ),
            tlv(
                0x30,
                &[
                    first.clone(),
                    second.clone(),
                    field(&prefix, 3, &[0x02, 0x01, 0]),
                ]
                .concat(),
            ),
            tlv(
                0x30,
                &[
                    first.clone(),
                    second.clone(),
                    field(&prefix, 3, &[0x01, 0x01, 1]),
                ]
                .concat(),
            ),
            tlv(
                0x30,
                &[
                    first.clone(),
                    second.clone(),
                    third.clone(),
                    field(&prefix, 4, &[0x01, 0x01, 0]),
                ]
                .concat(),
            ),
            tlv(0x31, &[first, second, third].concat()),
        ];
        for (i, config) in invalid.iter().enumerate() {
            assert!(
                SgxPckExtension::from_der(&with_profile(2, true, Some(config))).is_err(),
                "case {i}"
            );
        }
    }

    #[test]
    fn pck_extension_rejects_unknown_sgx_type() {
        let mut der = fixture_extension();
        let offset = sgx_type_value_offset(&der);
        der[offset] = 3;
        let error = SgxPckExtension::from_der(&der).unwrap_err();
        assert!(format!("{error:#}").contains("unknown SGX type"));
    }

    #[test]
    fn pck_extension_requires_enumerated_sgx_type() {
        let mut der = fixture_extension();
        let offset = sgx_type_value_offset(&der);
        der[offset - 2] = 0x02; // INTEGER is not ENUMERATED, even for value 2.
        der[offset] = 2;
        let error = SgxPckExtension::from_der(&der).unwrap_err();
        assert!(format!("{error:#}").contains("malformed extension value"));
    }
}
