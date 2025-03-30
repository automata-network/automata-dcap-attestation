use std::ops::Deref;

use anchor_client::{solana_sdk::{commitment_config::CommitmentConfig, compute_budget::ComputeBudgetInstruction, signature::{Keypair, Signature}, signer::Signer}, Client, Program};
use anchor_lang::{declare_program, prelude::Pubkey, AccountDeserialize};

declare_program!(automata_dcap_verifier);
use automata_dcap_verifier::{client::accounts, client::args};
use dcap_rs::{types::{quote::{Quote, SGX_TEE_TYPE, TDX_TEE_TYPE}, tcb_info::TcbInfoAndSignature}, verify_tcb_status};
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use x509_cert::{crl::CertificateList, serial_number::SerialNumber};
use x509_cert::der::Decode;
use x509_verify::VerifyingKey;
use zerocopy::AsBytes;


use crate::{get_issuer_common_name, get_secp256r1_instruction, CertificateAuthority, PccsClient, TcbType, PCCS_PROGRAM_ID};

const PLATFORM_ISSUER_NAME: &str = "Intel SGX PCK Platform CA";
const PROCESSOR_ISSUER_NAME: &str = "Intel SGX PCK Processor CA";
const ROOT_ISSUER_NAME: &str = "Intel SGX Root CA";

/// A client for the Verifier program.
///
/// It helps to interact with the Verifier program on the Solana blockchain.
pub struct VerifierClient<S> {
    program: Program<S>,
    pccs_client: PccsClient<S>,
}

impl<S: Clone + Deref<Target = impl Signer>> VerifierClient<S> {
    pub fn new(signer: S) -> anyhow::Result<Self> {
        let client = Client::new_with_options(
            anchor_client::Cluster::Localnet,
            signer.clone(),
            CommitmentConfig::confirmed(),
        );

        let program = client.program(automata_dcap_verifier::ID)?;
        let pccs_client = PccsClient::new(signer)?;

        Ok(Self { program, pccs_client })
    }

    pub async fn init_quote_buffer(
        &self,
        total_size: u32,
        num_chunks: u8,
    ) -> anyhow::Result<Pubkey> {
        let quote_buffer_keypair = Keypair::new();
        let quote_buffer_pubkey = quote_buffer_keypair.pubkey();

        let _tx = self
            .program
            .request()
            .accounts(accounts::InitQuoteBuffer {
                owner: self.program.payer(),
                data_buffer: quote_buffer_pubkey,
                system_program: anchor_client::solana_sdk::system_program::ID,
            })
            .args(args::InitQuoteBuffer {
                total_size,
                num_chunks,
            })
            .signer(quote_buffer_keypair)
            .send()
            .await?;

        Ok(quote_buffer_pubkey)
    }

    pub async fn upload_chunks(
        &self,
        quote_buffer_pubkey: Pubkey,
        data: &[u8],
        chunk_size: usize,
    ) -> anyhow::Result<()> {
        for (i, chunk) in data.chunks(chunk_size).enumerate() {
            let chunk_index = i as u8;
            let offset = i as u32 * chunk_size as u32;
            let chunk_data = chunk.to_vec();

            let tx = self
                .program
                .request()
                .accounts(accounts::AddQuoteChunk {
                    owner: self.program.payer(),
                    data_buffer: quote_buffer_pubkey,
                })
                .args(args::AddQuoteChunk {
                    chunk_index,
                    offset,
                    chunk_data,
                })
                .send()
                .await?;

            println!("Transaction signature: {}", tx);
        }
        Ok(())
    }

    pub async fn verify_quote(
        &self,
        quote_buffer_pubkey: Pubkey,
    ) -> anyhow::Result<Vec<Signature>> {

        // Parse Quote
        let quote_data = self.get_account::<automata_dcap_verifier::accounts::DataBuffer>(quote_buffer_pubkey).await?;
        let mut quote_data_bytes = quote_data.data.as_slice();
        let quote = Quote::read(&mut quote_data_bytes)?;

        let mut signatures = Vec::new();

        // Verify quote integrity
        let tx = self.verify_quote_integrity(quote_buffer_pubkey, &quote).await?;
        signatures.push(tx);

        // Verify ISV signature
        let tx = self.verify_quote_isv_signature(quote_buffer_pubkey, &quote).await?;
        signatures.push(tx);

        // Verify enclave source
        let tx = self.verify_quote_enclave_source(quote_buffer_pubkey, &quote).await?;
        signatures.push(tx);

        // Verify PCK cert chain. Please note that the verification of the signature is done off-chain here
        // as the certificate bytes are really large and we hit 1232 bytes limit of solana in general, when
        // we create a secp256r1 program instruction. We go and fetch the CRL certificates from the PCCS program
        // and do off-chain validation to make sure that the certificate in PCK chain is not revoked.
        self.verify_pck_cert_chain(&quote).await?;

        // Verify TCB status. This is done off-chain as well. Mainly due to the fact that parsing the TCB info
        // is a heavy computation and we go out of memory in solana.
        self.verify_tcb_status(&quote).await?;

        Ok(signatures)
    }

    async fn verify_quote_integrity(&self, quote_buffer_pubkey: Pubkey, quote: &Quote<'_>) -> anyhow::Result<Signature> {
        let pck_cert_chain_data = quote.signature.get_pck_cert_chain()?;
        let pck_pk_bytes = pck_cert_chain_data.pck_cert_chain[0]
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .unwrap_or_default();

        let pck_pkey = P256VerifyingKey::from_sec1_bytes(pck_pk_bytes).unwrap();
        let pubkey = pck_pkey.to_encoded_point(true).to_bytes();

        let qe_report_signature = P256Signature::from_slice(quote.signature.qe_report_signature).unwrap();
        let qe_report_signature_bytes = match qe_report_signature.normalize_s() {
            Some(sig) => sig.to_bytes(),
            None => qe_report_signature.to_bytes(),
        };

        let secp256r1_instruction_for_qe_report_body = get_secp256r1_instruction(
            &pubkey,
            quote.signature.qe_report_body.as_bytes(),
            &qe_report_signature_bytes,
        );

        let tx = self
            .program
            .request()
            .instruction(secp256r1_instruction_for_qe_report_body)
            .accounts(accounts::VerifyDcapQuoteIntegrity {
                owner: self.program.payer(),
                quote_data_buffer: quote_buffer_pubkey,
                instructions_sysvar: anchor_client::solana_sdk::sysvar::instructions::ID,
            })
            .args(args::VerifyDcapQuoteIntegrity {})
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("failed to verify quote integrity: {}", e))?;

        Ok(tx)
    }

    async fn verify_quote_isv_signature(&self, quote_buffer_pubkey: Pubkey, quote: &Quote<'_>) -> anyhow::Result<Signature> {
        let mut key = vec![0x4];
        key.extend_from_slice(&quote.signature.attestation_pub_key);
        let attestation_key = P256VerifyingKey::from_sec1_bytes(&key).unwrap();
        let attestation_key_bytes = attestation_key.to_encoded_point(true).to_bytes();

        let header_bytes = quote.header.as_bytes();
        let body_bytes = quote.body.as_bytes();
        let mut data = Vec::with_capacity(header_bytes.len() + body_bytes.len());
        data.extend_from_slice(header_bytes);
        data.extend_from_slice(body_bytes);

        let sig = P256Signature::from_slice(quote.signature.isv_signature).unwrap();
        let sig_bytes = match sig.normalize_s() {
            Some(sig) => sig.to_bytes(),
            None => sig.to_bytes(),
        };

        let secp256r1_instruction_for_attestation_pub_key = get_secp256r1_instruction(
            &attestation_key_bytes,
            &data,
            &sig_bytes
        );

        let tx = self
            .program
            .request()
            .instruction(secp256r1_instruction_for_attestation_pub_key)
            .accounts(accounts::VerifyDcapQuoteIsvSignature {
                owner: self.program.payer(),
                quote_data_buffer: quote_buffer_pubkey,
                instructions_sysvar: anchor_client::solana_sdk::sysvar::instructions::ID,
            })
            .args(args::VerifyDcapQuoteIsvSignature {})
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("failed to verify quote isv signature: {}", e))?;

        Ok(tx)
    }

    async fn verify_quote_enclave_source(&self, quote_buffer_pubkey: Pubkey, quote: &Quote<'_>) -> anyhow::Result<Signature> {

        let (qe_type, qe_version) = match quote.header.tee_type {
            SGX_TEE_TYPE => ("QE".to_string(), 3 as u8),
            TDX_TEE_TYPE => ("TD_QE".to_string(), 2 as u8),
            _ => return Err(anyhow::anyhow!("unsupported tee type")),
        };


        let qe_identity_pda = Pubkey::find_program_address(
            &[b"enclave_identity", qe_type.as_bytes(), &qe_version.to_le_bytes()[..1]],
            &PCCS_PROGRAM_ID
        ).0;

        let tx = self
            .program
            .request()
            .accounts(accounts::VerifyDcapQuoteEnclaveSource {
                owner: self.program.payer(),
                quote_data_buffer: quote_buffer_pubkey,
                qe_identity_pda: qe_identity_pda,
            })
            .args(args::VerifyDcapQuoteEnclaveSource {
                _qe_type: qe_type.to_string(),
                _version: qe_version,
            })
            .send().await?;

        Ok(tx)
    }

    async fn verify_pck_cert_chain(&self, quote: &Quote<'_>) -> anyhow::Result<()> {
        let pck_cert_chain_data = quote.signature.get_pck_cert_chain()?;


        let cert_chain_size = pck_cert_chain_data.pck_cert_chain.len();
        for (index, cert) in pck_cert_chain_data.pck_cert_chain.iter().enumerate() {

            let issuer = if index == cert_chain_size - 1 {
                cert
            } else {
                &pck_cert_chain_data.pck_cert_chain[index + 1]
            };

            // Need to check if the certificate is not revoked.
            let issuer_common_name = get_issuer_common_name(&cert.tbs_certificate)
                .ok_or_else(|| anyhow::anyhow!("Certificate missing Common Name in issuer field"))?;

            match issuer_common_name.as_str() {
                PLATFORM_ISSUER_NAME => {
                    // Get the PLATFORM CRL from the PCCS program
                    self.check_certificate_revocation(&cert.tbs_certificate.serial_number, CertificateAuthority::PLATFORM).await?;
                },
                PROCESSOR_ISSUER_NAME => {
                    // Get the PROCESSOR CRL from the PCCS program
                    self.check_certificate_revocation(&cert.tbs_certificate.serial_number, CertificateAuthority::PROCESSOR).await?;
                },
                ROOT_ISSUER_NAME => {
                    // Get the ROOT CRL from the PCCS program
                    self.check_certificate_revocation(&cert.tbs_certificate.serial_number, CertificateAuthority::ROOT).await?;
                },
                other => return Err(anyhow::anyhow!("Unsupported issuer common name: {}", other)),
            }

            let pk: VerifyingKey= (issuer)
                .try_into()
                .map_err(|e| anyhow::anyhow!("failed to decode key from certificate: {}", e))?;

            pk.verify_strict(cert)
                .map_err(|e| anyhow::anyhow!("failed to verify certificate: {}, error: {}", cert.tbs_certificate.subject.to_string(), e))?;
        }
        Ok(())

    }

    async fn verify_tcb_status(&self, quote: &Quote<'_>) -> anyhow::Result<()> {
        let pck_extension = quote.signature.get_pck_extension()?;
        let fmspc = hex::encode(pck_extension.fmspc);
        let version = 3 as u8;
        let tcb_type = if quote.header.tee_type == SGX_TEE_TYPE {
            TcbType::Sgx
        } else {
            TcbType::Tdx
        };
        let tcb_info_data = self.pccs_client.get_tcb_info_data(tcb_type, fmspc, version).await?;
        let tcb_info: TcbInfoAndSignature = serde_json::from_slice(&tcb_info_data)?;
        let tcb_info = tcb_info.get_tcb_info()?;

        let _tcb_status = verify_tcb_status(&tcb_info, &pck_extension)?;

        Ok(())
    }

    async fn check_certificate_revocation(
        &self,
        serial_number: &SerialNumber,
        ca_type: CertificateAuthority
    ) -> anyhow::Result<()> {
        let pcs_cert_data = self.pccs_client.get_pcs_certificate_data(ca_type, true).await?;
        let certificate_list = CertificateList::from_der(&pcs_cert_data)?;

        if let Some(crl) = certificate_list.tbs_cert_list.revoked_certificates {
            for revoked_cert in crl {
                if revoked_cert.serial_number == *serial_number {
                    return Err(anyhow::anyhow!("Certificate is revoked"));
                }
            }
        }

        Ok(())
    }

    pub fn get_payer(&self) -> Pubkey {
        self.program.payer().clone()
    }

    pub async fn get_account<T: AccountDeserialize>(&self, pubkey: Pubkey) -> anyhow::Result<T> {
        let account = self
            .program
            .account::<T>(pubkey)
            .await?;
        Ok(account)
    }
}
