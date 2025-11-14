#[cfg(feature = "zero-copy")]
use crate::utils::cert_chain_processor;
use crate::utils::keccak;
use crate::utils::{cert_chain, crl};
use alloy_sol_types::{SolType, sol};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use x509_cert::certificate::CertificateInner;
use x509_cert::{
    crl::CertificateList,
    der::{Decode, Encode},
};

use super::{enclave_identity::QuotingEnclaveIdentityAndSignature, tcb_info::TcbInfoAndSignature};

pub type CollateralSol = sol!((bytes, bytes, bytes[2], string, string));

#[derive(Debug, Serialize, Deserialize)]
pub struct Collateral {
    /* Certificate Revocation List */
    /// Root CA CRL in PEM format
    /// Contains a list of revoked certificates signed by Intel SGX Root CA.
    /// It is used to check if any certificates in the verification chain have been revoked.
    #[serde(with = "crl")]
    pub root_ca_crl: CertificateList,

    /// PCK CRL in PEM format
    ///
    /// This can be Platform CA CRL or Processor CA CRL.
    /// Contains a list of revoked certificates signed by Intel SGX Platform CA or Intel SGX Processor CA.
    /// It is used to check if any certificates in the verification chain have been revoked.
    /// Only to be passed if the quote is expected to be signed by Intel SGX PCK CA.
    #[serde(with = "crl")]
    pub pck_crl: CertificateList,

    /* Issuer Certificate Chains */
    /// TCB Info and Identity Issuer Chain in PEM format
    /// Chain of certificates used to verify TCB Info and Identity signature.
    #[serde(with = "cert_chain")]
    pub tcb_info_and_qe_identity_issuer_chain: Vec<CertificateInner>,

    /* Structured Data */
    /// TCB Info Structure
    /// Contains security version information and TCB levels.
    pub tcb_info: TcbInfoAndSignature,

    /// QE Identity Structure
    /// Contains Quoting Enclave identity information.
    pub qe_identity: QuotingEnclaveIdentityAndSignature,
}

impl Collateral {
    pub fn new(
        root_ca_crl_der: &[u8],
        pck_crl_der: &[u8],
        tcb_info_and_qe_identity_issuer_chain_pem_bytes: &[u8],
        tcb_info_json_str: &str,
        qe_identity_json_str: &str,
    ) -> Result<Self> {
        let root_ca_crl = CertificateList::from_der(root_ca_crl_der)?;
        let pck_crl = CertificateList::from_der(pck_crl_der)?;
        #[cfg(not(feature = "zero-copy"))]
        let tcb_info_and_qe_identity_issuer_chain: Vec<CertificateInner> =
            CertificateInner::load_pem_chain(tcb_info_and_qe_identity_issuer_chain_pem_bytes)?;
        #[cfg(feature = "zero-copy")]
        let tcb_info_and_qe_identity_issuer_chain: Vec<CertificateInner> =
            cert_chain_processor::load_pem_chain_bpf_friendly(
                tcb_info_and_qe_identity_issuer_chain_pem_bytes,
            )?;
        let tcb_info: TcbInfoAndSignature = serde_json::from_str(tcb_info_json_str)?;
        let qe_identity: QuotingEnclaveIdentityAndSignature =
            serde_json::from_str(qe_identity_json_str)?;

        Ok(Self {
            root_ca_crl,
            pck_crl,
            tcb_info_and_qe_identity_issuer_chain,
            tcb_info,
            qe_identity,
        })
    }

    pub fn get_cert_hash(cert: &CertificateInner) -> Result<[u8; 32]> {
        let tbs = cert.tbs_certificate.to_der()?;
        Ok(keccak::hash(&tbs))
    }

    pub fn get_crl_hash(crl: &CertificateList) -> Result<[u8; 32]> {
        let tbs = crl.tbs_cert_list.to_der()?;
        Ok(keccak::hash(&tbs))
    }

    /// Encode the Collateral struct to Solidity ABI format
    pub fn sol_abi_encode(&self) -> Result<Vec<u8>> {
        // Convert CRLs to DER-encoding raw bytes for ABI encoding
        let root_ca_crl_bytes = self.root_ca_crl.to_der()?;
        let pck_crl_bytes = self.pck_crl.to_der()?;

        // Encode certificate chain as ABI-encoded DER bytes array (of fixed size == 2)
        let tcb_issuer_chain = &self.tcb_info_and_qe_identity_issuer_chain;
        let mut chain_bytes: [Vec<u8>; 2] = [vec![], vec![]];
        for (i, cert) in tcb_issuer_chain.iter().enumerate() {
            let cert_der = cert.to_der()?;
            chain_bytes[i] = cert_der;
        }

        // Serialize structured data to JSON strings
        let tcb_info_json = serde_json::to_string(&self.tcb_info)?;
        let qe_identity_json = serde_json::to_string(&self.qe_identity)?;

        // Create tuple for ABI encoding: (bytes, bytes, bytes[2], string, string)
        let encoded = CollateralSol::abi_encode_params(&(
            root_ca_crl_bytes,
            pck_crl_bytes,
            chain_bytes,
            tcb_info_json,
            qe_identity_json,
        ));
        Ok(encoded)
    }

    /// Decode Solidity ABI encoded bytes back to Collateral struct
    pub fn sol_abi_decode(encoded: &[u8]) -> Result<Self> {
        use pem::{Pem, encode};

        // Decode the ABI encoded tuple: (bytes, bytes, bytes, string, string)
        let (root_ca_crl_bytes, pck_crl_bytes, chain_bytes, tcb_info_json, qe_identity_json) =
            CollateralSol::abi_decode_params(encoded)?;

        let mut pem_chain = String::new();
        let tcb_pem = Pem::new(String::from("CERTIFICATE"), chain_bytes[0].to_vec().clone());

        let root_pem = Pem::new(String::from("CERTIFICATE"), chain_bytes[1].to_vec().clone());

        pem_chain.push_str(&encode(&tcb_pem));
        pem_chain.push_str(&encode(&root_pem));

        Self::new(
            &root_ca_crl_bytes,
            &pck_crl_bytes,
            pem_chain.as_bytes(),
            &tcb_info_json,
            &qe_identity_json,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::Collateral;

    #[test]
    fn test_encode_collateral() {
        let collateral = Collateral::new(
            include_bytes!("../../data/intel_root_ca_crl.der"),
            include_bytes!("../../data/pck_platform_crl.der"),
            include_bytes!("../../data/tcb_signing_cert.pem"),
            include_str!("../../data/tcb_info_v2.json"),
            include_str!("../../data/qeidentityv2.json"),
        )
        .expect("collateral to be created");

        let json = serde_json::to_string(&collateral).expect("collateral to serialize");
        assert!(!json.is_empty(), "collateral JSON should not be empty");
        println!("Collateral JSON: {}", json);
    }

    #[test]
    fn test_decode_collateral_json() {
        let json = include_str!("../../data/full_collateral_sgx.json");
        let _collateral: Collateral = serde_json::from_str(json).expect("json to parse");
    }

    #[test]
    fn test_abi_encode_collateral() {
        let collateral = Collateral::new(
            include_bytes!("../../data/intel_root_ca_crl.der"),
            include_bytes!("../../data/pck_platform_crl.der"),
            include_bytes!("../../data/tcb_signing_cert.pem"),
            include_str!("../../data/tcb_info_v2.json"),
            include_str!("../../data/qeidentityv2.json"),
        )
        .expect("collateral to be created");

        let encoded = collateral
            .sol_abi_encode()
            .expect("collateral to abi encode");
        assert!(!encoded.is_empty(), "ABI encoded data should not be empty");

        // Write encoded data to file for test_abi_decode_collateral to use
        std::fs::create_dir_all("data/abi/").expect("failed to create directory");
        std::fs::write("data/abi/encoded.bin", &encoded).expect("failed to write encoded data");

        println!("ABI encoded length: {} bytes", encoded.len());
    }

    #[test]
    fn test_abi_decode_collateral() {
        // Read the encoded data written by test_abi_encode_collateral
        let encoded = std::fs::read("data/abi/encoded.bin").expect("failed to read encoded data");
        let decoded = Collateral::sol_abi_decode(&encoded).expect("collateral to abi decode");

        // Create original collateral for comparison
        let original = Collateral::new(
            include_bytes!("../../data/intel_root_ca_crl.der"),
            include_bytes!("../../data/pck_platform_crl.der"),
            include_bytes!("../../data/tcb_signing_cert.pem"),
            include_str!("../../data/tcb_info_v2.json"),
            include_str!("../../data/qeidentityv2.json"),
        )
        .expect("collateral to be created");

        // Verify the decoded data matches original
        let original_json = serde_json::to_string(&original).expect("original to serialize");
        let decoded_json = serde_json::to_string(&decoded).expect("decoded to serialize");
        assert_eq!(
            original_json, decoded_json,
            "Decoded collateral should match original"
        );
    }
}
