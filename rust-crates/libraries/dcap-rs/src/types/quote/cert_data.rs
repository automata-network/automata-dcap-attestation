use anyhow::{Context, anyhow};
use p256::ecdsa::Signature;
use x509_cert::certificate::CertificateInner;
use zerocopy::little_endian;

use crate::{
    types::{report::EnclaveReportBody, sgx_x509::SgxPckExtension},
    utils::{self, cert_chain_processor},
};

#[derive(Debug)]
pub struct QuoteCertData<'a> {
    /// Type of cert key
    pub cert_key_type: little_endian::U16,

    /// Size of the cert data
    pub cert_data_size: little_endian::U32,

    /// Cert data
    pub cert_data: &'a [u8],
}

impl<'a> QuoteCertData<'a> {
    pub fn read(bytes: &mut &'a [u8]) -> anyhow::Result<Self> {
        let cert_key_type = utils::read_from_bytes::<little_endian::U16>(bytes)
            .ok_or_else(|| anyhow!("incorrect buffer size"))?;

        let cert_data_size = utils::read_from_bytes::<little_endian::U32>(bytes)
            .ok_or_else(|| anyhow!("incorrect buffer size"))?;

        let cert_data = utils::read_bytes(bytes, cert_data_size.get() as usize);

        Ok(Self {
            cert_key_type,
            cert_data_size,
            cert_data,
        })
    }

    pub fn as_pck_cert_chain_data(&self) -> anyhow::Result<PckCertChainData> {
        if self.cert_key_type.get() != CertificationKeyType::PckCertChain as u16 {
            return Err(anyhow!(
                "cannot transform cert data into pck cert chain data"
            ));
        }

        let cert_data = self.cert_data.strip_suffix(&[0]).unwrap_or(self.cert_data);
        let pck_cert_chain = cert_chain_processor::load_pem_chain_bpf_friendly(cert_data)
            .context("Failed to parse PCK certificate chain")?;

        let pck_extension = pck_cert_chain
            .first()
            .context("CertChain")?
            .tbs_certificate
            .extensions
            .as_ref()
            .and_then(|extensions| {
                extensions
                    .iter()
                    .find(|ext| SgxPckExtension::is_pck_ext(ext.extn_id.to_string()))
            })
            .ok_or_else(|| anyhow!("PCK Certificate does not contain a SGX Extension"))?;

        let pck_extension = SgxPckExtension::from_der(pck_extension.extn_value.as_bytes())
            .context("PCK Extension")?;

        Ok(PckCertChainData {
            pck_cert_chain,
            pck_extension,
        })
    }

    pub fn get_pck_extension(&self) -> anyhow::Result<SgxPckExtension> {
        let first_cert = cert_chain_processor::load_first_cert_from_pem_data(self.cert_data)
            .context("Failed to parse PCK certificate chain")?;

        let pck_extension = first_cert
            .tbs_certificate
            .extensions
            .as_ref()
            .and_then(|extensions| {
                extensions
                    .iter()
                    .find(|ext| SgxPckExtension::is_pck_ext(ext.extn_id.to_string()))
            })
            .ok_or_else(|| anyhow!("PCK Certificate does not contain a SGX Extension"))?;

        let pck_extension = SgxPckExtension::from_der(pck_extension.extn_value.as_bytes())
            .context("PCK Extension")?;

        Ok(pck_extension)
    }
}

pub struct QuotingEnclaveReportCertData<'a> {
    pub qe_report: EnclaveReportBody,

    pub qe_report_signature: Signature,

    pub qe_auth_data: &'a [u8],

    pub pck_cert_chain_data: PckCertChainData,
}

pub struct PckCertChainData {
    pub pck_cert_chain: Vec<CertificateInner>,

    pub pck_extension: SgxPckExtension,
}

#[derive(Debug, PartialEq)]
pub enum CertificationKeyType {
    _PpidClearText = 1,
    _PpidRsa2048Encrypted,
    _PpidRsa3072Encrypted,
    _PckCleartext,
    PckCertChain,
    EcdsaSigAuxData,
}
