use std::ops::Deref;

use anchor_client::{
    Client, Program,
    solana_sdk::{
        compute_budget::ComputeBudgetInstruction,
        signature::{Keypair, Signature},
        signer::Signer,
    },
};
use anchor_lang::{declare_program, prelude::Pubkey};

declare_program!(automata_dcap_verifier);
use automata_dcap_verifier::accounts::VerifiedOutput as VerifiedOutputAccount;
use automata_dcap_verifier::types::ZkvmSelector;
use automata_dcap_verifier::{client::accounts, client::args};
use dcap_rs::types::quote::{Quote, QuoteBody, SGX_TEE_TYPE, TDX_TEE_TYPE};
use dcap_rs::types::report::{EnclaveReportBody, Td10ReportBody};
use dcap_rs::types::{VerifiedOutput, tcb_info::*};
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use zerocopy::AsBytes;

use crate::pccs::compute_pcs_pda_pubkey;
use crate::{TcbType, pccs::PCCS_PROGRAM_ID, shared::ecdsa::get_secp256r1_instruction};
use crate::CertificateAuthority;

/// A client for the Automata DCAP Verifier program on Solana.
///
/// This client provides functionality to interact with the DCAP (Data Center Attestation Primitives)
/// Verifier program on the Solana blockchain. It facilitates the verification of Intel SGX and TDX
/// attestation quotes, handling buffer management, quote verification steps, and certificate chain validation.
///
/// The verification process includes several steps:
/// - Initializing a buffer for storing quote data
/// - Uploading quote data in chunks
/// - Verifying the integrity of the quote
/// - Verifying the ISV (Independent Software Vendor) signature
/// - Verifying the enclave source, and checking the TCB Status for the Quoting Enclave (QE)
/// - Verifying the PCK (Provisioning Certification Key) certificate chain
/// - Checks the TCB Status for the platform
/// 
/// And finally, the client also provides a function that post-processes the verification results.
pub struct VerifierClient<S> {
    pub program: Program<S>,
}

impl<S: Clone + Deref<Target = impl Signer>> VerifierClient<S> {
    pub fn new(client: &Client<S>) -> anyhow::Result<Self> {
        let program = client.program(automata_dcap_verifier::ID)?;

        Ok(Self { program })
    }

    /// Initializes a buffer account for storing quote data, and creates a corresponding VerifiedOutput PDA
    /// 
    /// # Parameters
    /// - `quote_size`: The size of the quote data to be stored in the buffer
    /// 
    /// # Returns
    /// - `Result<(Pubkey, Pubkey)>`: A tuple containing the public key of the buffer account and the verified output PDA
    pub async fn init_quote_buffer(&self, quote_size: u32) -> anyhow::Result<(Pubkey, Pubkey)> {
        let quote_buffer_keypair = Keypair::new();
        let quote_buffer_pubkey = quote_buffer_keypair.pubkey();

        let verified_output_key = self.get_verified_output_pubkey(quote_buffer_pubkey).await?;

        let _tx = self
            .program
            .request()
            .accounts(accounts::CreateQuoteAccounts {
                owner: self.program.payer(),
                quote_data_buffer: quote_buffer_pubkey,
                verified_output: verified_output_key,
                system_program: anchor_client::solana_sdk::system_program::ID,
            })
            .args(args::CreateQuoteAccounts { quote_size })
            .signer(quote_buffer_keypair)
            .send()
            .await?;

        Ok((quote_buffer_pubkey, verified_output_key))
    }

    /// Uploads quote data to the buffer account in chunks.
    ///
    /// This method takes the raw quote data and uploads it to the previously initialized buffer account
    /// in chunks of the specified size. This chunking approach is necessary due to Solana transaction
    /// size limitations.
    ///
    /// # Parameters
    /// - `quote_buffer_pubkey`: The public key of the buffer account initialized with `init_quote_buffer`
    /// - `data`: The raw DCAP quote data to upload
    /// - `chunk_size`: The size of each chunk for upload (in bytes)
    ///
    /// # Returns
    /// - `Result<()>`: Success or an error if upload fails
    pub async fn upload_chunks(
        &self,
        quote_buffer_pubkey: Pubkey,
        data: &[u8],
        chunk_size: usize,
    ) -> anyhow::Result<()> {
        for (i, chunk) in data.chunks(chunk_size).enumerate() {
            let offset = i as u32 * chunk_size as u32;
            let chunk_data = chunk.to_vec();

            let tx = self
                .program
                .request()
                .accounts(accounts::AddQuoteChunk {
                    owner: self.program.payer(),
                    data_buffer: quote_buffer_pubkey,
                })
                .args(args::AddQuoteChunk { offset, chunk_data })
                .send()
                .await?;

            println!("Transaction signature: {}", tx);
        }
        Ok(())
    }

    /// Deletes (or more accurately, closes) the quote buffer and VerifiedOutput accounts to claim rent.
    /// 
    /// # Parameters
    /// - `quote_buffer_pubkey`: The public key of the buffer account to be closed
    /// - `verified_output_pubkey`: The public key of the VerifiedOutput account to be closed
    /// 
    /// # Returns
    /// - `Result<()>`: Success or an error if the deletion fails
    pub async fn delete_quote_buffer(
        &self,
        quote_buffer_pubkey: Pubkey,
        verified_output_pubkey: Pubkey,
    ) -> anyhow::Result<()> {
        let _tx = self
            .program
            .request()
            .accounts(accounts::CloseQuoteAccounts {
                owner: self.program.payer(),
                quote_data_buffer: quote_buffer_pubkey,
                verified_output: verified_output_pubkey,
                system_program: anchor_client::solana_sdk::system_program::ID,
            })
            .args(args::CloseQuoteAccounts {})
            .send()
            .await?;

        Ok(())
    }

    /// Verifies a DCAP quote through multiple verification steps.
    ///
    /// This is the main verification method that orchestrates the entire verification process.
    /// It performs a series of verification steps, each addressing a different aspect of the quote's
    /// trustworthiness and validity.
    ///
    /// The verification process includes:
    /// 1. Quote integrity verification
    /// 2. ISV signature verification
    /// 3. Enclave source verification
    /// 4. PCK certificate chain verification (performed off-chain)
    /// 5. TCB status matching
    ///
    /// # Parameters
    /// - `quote_buffer_pubkey`: The public key of the buffer account containing the quote data
    /// - `verified_output_pubkey`: The public key of the VerifiedOutput account
    /// - `zkvm_verifier_program`: The public key of the ZKVM verifier program
    /// - `zkvm_selector`: The ZKVM selector (currently only supports RiscZero)
    /// - `pck_cert_chain_verify_proof_bytes`: The SNARK proof bytes for the PCK certificate chain verification
    /// 
    /// # Returns
    /// - `Result<Vec<Signature>>`: A vector of transaction signatures for each verification step,
    ///   or an error if any verification step fails
    pub async fn verify_quote(
        &self,
        quote_buffer_pubkey: Pubkey,
        verified_output_pubkey: Pubkey,
        zkvm_verifier_program: Pubkey,
        zkvm_selector: ZkvmSelector,
        pck_cert_chain_verify_proofs: [Vec<u8>; 3],
    ) -> anyhow::Result<Vec<Signature>> {
        // Parse Quote
        let quote_data = self
            .program
            .account::<automata_dcap_verifier::accounts::DataBuffer>(quote_buffer_pubkey)
            .await?;
        let mut quote_data_bytes = quote_data.data.as_slice();
        let quote = Quote::read(&mut quote_data_bytes)?;

        let mut signatures = Vec::new();

        // Verify quote integrity
        let tx = self
            .verify_quote_integrity(quote_buffer_pubkey, verified_output_pubkey, &quote)
            .await?;
        signatures.push(tx);

        // Verify ISV signature
        let tx = self
            .verify_quote_isv_signature(quote_buffer_pubkey, verified_output_pubkey, &quote)
            .await?;
        signatures.push(tx);

        // Verify enclave source
        let tx = self
            .verify_quote_enclave_source(quote_buffer_pubkey, verified_output_pubkey, &quote)
            .await?;
        signatures.push(tx);

        self.verify_pck_cert_chain(
            quote_buffer_pubkey,
            verified_output_pubkey,
            zkvm_verifier_program,
            zkvm_selector,
            pck_cert_chain_verify_proofs,
        )
        .await?;

        // Verify TCB status
        let tx = self
            .verify_tcb_status(quote_buffer_pubkey, verified_output_pubkey, &quote)
            .await?;
        signatures.push(tx);

        Ok(signatures)
    }

    /// Verifies the integrity of the DCAP quote.
    ///
    /// This method validates that the quote structure is intact and correctly signed. It extracts
    /// the PCK certificate from the quote, uses the public key to verify the QE (Quoting Enclave) report
    /// signature, and submits a transaction to the verifier program for on-chain verification.
    /// 
    /// It also determines the QE type and version from the quote's header, and writes to VerifiedOutput.
    ///
    /// # Parameters
    /// - `quote_buffer_pubkey`: The public key of the buffer account containing the quote data
    /// - `verified_output_pubkey`: The public key of the VerifiedOutput account
    /// - `quote`: The parsed Quote object to verify
    ///
    /// # Returns
    /// - `Result<Signature>`: The transaction signature for this verification step,
    ///   or an error if verification fails
    async fn verify_quote_integrity(
        &self,
        quote_buffer_pubkey: Pubkey,
        verified_output_pubkey: Pubkey,
        quote: &Quote<'_>,
    ) -> anyhow::Result<Signature> {
        let pck_cert_chain_data = quote.signature.get_pck_cert_chain()?;
        let pck_pk_bytes = pck_cert_chain_data.pck_cert_chain[0]
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .unwrap_or_default();

        let pck_pkey = P256VerifyingKey::from_sec1_bytes(pck_pk_bytes).unwrap();
        let pubkey = pck_pkey.to_encoded_point(true).to_bytes();

        let qe_report_signature =
            P256Signature::from_slice(quote.signature.qe_report_signature).unwrap();
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
            .instruction(ComputeBudgetInstruction::set_compute_unit_limit(1_000_000))
            .accounts(accounts::VerifyDcapQuoteIntegrity {
                quote_data_buffer: quote_buffer_pubkey,
                verified_output: verified_output_pubkey,
                instructions_sysvar: anchor_client::solana_sdk::sysvar::instructions::ID,
            })
            .args(args::VerifyDcapQuoteIntegrity {})
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("failed to verify quote integrity: {}", e))?;

        Ok(tx)
    }

    /// Verifies the ISV (Independent Software Vendor) signature in the DCAP quote.
    ///
    /// This method verifies that the quote was correctly signed by the attesting enclave's private key.
    /// It extracts the attestation public key from the quote, constructs the data to be verified,
    /// and submits a transaction to the verifier program for on-chain signature verification.
    ///
    /// # Parameters
    /// - `quote_buffer_pubkey`: The public key of the buffer account containing the quote data
    /// - `verified_output_pubkey`: The public key of the VerifiedOutput account
    /// - `quote`: The parsed Quote object to verify
    ///
    /// # Returns
    /// - `Result<Signature>`: The transaction signature for this verification step,
    ///   or an error if verification fails
    async fn verify_quote_isv_signature(
        &self,
        quote_buffer_pubkey: Pubkey,
        verified_output_pubkey: Pubkey,
        quote: &Quote<'_>,
    ) -> anyhow::Result<Signature> {
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

        let secp256r1_instruction_for_attestation_pub_key =
            get_secp256r1_instruction(&attestation_key_bytes, &data, &sig_bytes);

        let tx = self
            .program
            .request()
            .instruction(secp256r1_instruction_for_attestation_pub_key)
            .accounts(accounts::VerifyDcapQuoteIsvSignature {
                quote_data_buffer: quote_buffer_pubkey,
                verified_output: verified_output_pubkey,
                instructions_sysvar: anchor_client::solana_sdk::sysvar::instructions::ID,
            })
            .args(args::VerifyDcapQuoteIsvSignature {})
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("failed to verify quote isv signature: {}", e))?;

        Ok(tx)
    }

    /// Verifies the enclave source of the DCAP quote.
    ///
    /// This method verifies that the quote originates from a trusted Intel Quoting Enclave (QE).
    /// It determines the QE Identity by checking values, such as MRSIGNER, ISVPRODID etc using the corresponding
    /// enclave identity fetched from the PCCS program, and submits a transaction to the verifier program
    /// for on-chain verification.
    ///
    /// # Parameters
    /// - `quote_buffer_pubkey`: The public key of the buffer account containing the quote data
    /// - `verified_output_pubkey`: The public key of the VerifiedOutput account
    /// - `quote`: The parsed Quote object to verify
    ///
    /// # Returns
    /// - `Result<Signature>`: The transaction signature for this verification step,
    ///   or an error if verification fails
    async fn verify_quote_enclave_source(
        &self,
        quote_buffer_pubkey: Pubkey,
        verified_output_pubkey: Pubkey,
        quote: &Quote<'_>,
    ) -> anyhow::Result<Signature> {
        let (qe_type, qe_version) = match quote.header.tee_type {
            SGX_TEE_TYPE => ("QE".to_string(), 3 as u8),
            TDX_TEE_TYPE => ("TD_QE".to_string(), 2 as u8),
            _ => return Err(anyhow::anyhow!("unsupported tee type")),
        };

        let qe_identity_pda = Pubkey::find_program_address(
            &[
                b"enclave_identity",
                qe_type.as_bytes(),
                &qe_version.to_le_bytes()[..1],
            ],
            &PCCS_PROGRAM_ID,
        )
        .0;

        let tx = self
            .program
            .request()
            .accounts(accounts::VerifyDcapQuoteEnclaveSource {
                quote_data_buffer: quote_buffer_pubkey,
                qe_identity_pda: qe_identity_pda,
                verified_output: verified_output_pubkey,
            })
            .args(args::VerifyDcapQuoteEnclaveSource {
                _qe_type: qe_type.to_string(),
                _version: qe_version,
            })
            .send()
            .await?;

        Ok(tx)
    }

    /// Verifies the PCK certificate chain of the DCAP quote.
    /// 
    /// This method verifies that the PCK Certificate Chain attached to the quote has a valid root of trust.
    /// The chain verification itself is performed off-chain using a ZKVM (Zero-Knowledge Virtual Machine) proof.
    /// 
    /// # Parameters:
    /// - `quote_buffer_pubkey`: The public key of the buffer account containing the quote data
    /// - `verified_output_pubkey`: The public key of the VerifiedOutput account
    /// - `zkvm_verifier_program`: The public key of the ZKVM verifier program
    /// - `zkvm_selector`: The ZKVM selector (currently only supports RiscZero)
    /// - `proof_bytes`: The SNARK proof bytes for the PCK certificate chain verification
    /// 
    /// # Returns:
    /// - `Result<Signature>`: The transaction signature for this verification step,
    ///   or an error if verification fails
    async fn verify_pck_cert_chain(
        &self,
        quote_buffer_pubkey: Pubkey,
        verified_output_pubkey: Pubkey,
        zkvm_verifier_program: Pubkey,
        zkvm_selector: ZkvmSelector,
        proofs: [Vec<u8>; 3],
    ) -> anyhow::Result<Signature> {
        // TEMP
        let proof_bytes = proofs[0].clone();

        let tx = self.program
            .request()
            .accounts(accounts::VerifyPckCertChainZk {
                quote_data_buffer: quote_buffer_pubkey,
                zkvm_verifier_program,
                pck_crl: compute_pcs_pda_pubkey(CertificateAuthority::PLATFORM, true),
                root_crl: compute_pcs_pda_pubkey(CertificateAuthority::ROOT, true),
                verified_output: verified_output_pubkey,
                system_program: anchor_client::solana_sdk::system_program::ID,
            })
            .instruction(ComputeBudgetInstruction::set_compute_unit_limit(1_000_000))
            .args(args::VerifyPckCertChainZk {
                zkvm_selector,
                proof_bytes,
            })
            .send()
            .await?;

        Ok(tx)
    }

    /// Matches the TCB (Trusted Computing Base) status of the platform.
    ///
    /// This method verifies that the platform TCB (hardware, firmware, and software components)
    /// meets the required security level. Each component SVNs are matched against the TcbInfo
    /// Collateral fetched from the PCCS program to determine the TCB Status.
    /// 
    /// Additionally, TDX quotes also check the TCB Status based on the TCB of the TDX module.
    ///
    /// # Parameters
    /// - `quote`: The parsed Quote object to verify
    /// - `quote_buffer_pubkey`: The public key of the buffer account containing the quote data
    /// - `verified_output_pubkey`: The public key of the VerifiedOutput account
    /// - `quote`: The parsed Quote object to verify
    ///
    /// # Returns
    /// - `Result<Signature>`: The transaction signature for this verification step,
    ///   or an error if verification fails
    async fn verify_tcb_status(
        &self,
        quote_buffer_pubkey: Pubkey,
        verified_output_pubkey: Pubkey,
        quote: &Quote<'_>,
    ) -> anyhow::Result<Signature> {
        let version = 3 as u8;
        let tcb_type = if quote.header.tee_type == SGX_TEE_TYPE {
            TcbType::Sgx
        } else {
            TcbType::Tdx
        };
        let fmspc = quote.signature.get_pck_extension()?.fmspc;
        let tcb_info_pda = Pubkey::find_program_address(
            &[
                b"tcb_info",
                tcb_type.common_name().as_bytes(),
                &version.to_le_bytes()[..1],
                &fmspc,
            ],
            &PCCS_PROGRAM_ID,
        )
        .0;

        let tx = self
            .program
            .request()
            .instruction(ComputeBudgetInstruction::set_compute_unit_limit(5000000))
            .accounts(accounts::VerifyDcapQuoteTcbStatus {
                tcb_info_pda: tcb_info_pda,
                quote_data_buffer: quote_buffer_pubkey,
                verified_output: verified_output_pubkey,
            })
            .args(args::VerifyDcapQuoteTcbStatus {
                _tcb_type: tcb_type.common_name().to_string(),
                _version: version,
                fmspc,
            })
            .send()
            .await?;

        Ok(tx)
    }

    /// Returns the payer's public key associated with this client.
    ///
    /// # Returns
    /// - `Pubkey`: The public key of the payer
    pub fn get_payer(&self) -> Pubkey {
        self.program.payer().clone()
    }

    /// Gets the public key of the verified output account for a given quote buffer.
    ///
    /// This method calculates the Program Derived Address (PDA) for the verified output account
    /// associated with the given quote buffer.
    ///
    /// # Parameters
    /// - `quote_buffer_pubkey`: The public key of the quote buffer account
    ///
    /// # Returns
    /// - `Result<Pubkey>`: The public key of the verified output account,
    ///   or an error if the calculation fails
    pub async fn get_verified_output_pubkey(
        &self,
        quote_buffer_pubkey: Pubkey,
    ) -> anyhow::Result<Pubkey> {
        let verified_output_pda = Pubkey::find_program_address(
            &[b"verified_output", quote_buffer_pubkey.as_ref()],
            &self.program.id(),
        )
        .0;
        Ok(verified_output_pda)
    }

    /// Post-processes the verification result obtained from the verified output account.
    /// 
    /// This method ensures that the output is fully verified by checking various flags.
    /// Then, it performs TCB Status convergence to determine the final TCB Status.
    /// 
    /// # Parameters
    /// - `verified_output_pubkey`: The public key of the verified output account
    /// 
    /// # Returns
    /// - `Result<VerifiedOutput>`: The standard VerifiedOutput object used by our infrastructure.
    /// As defined in:
    /// - dcap_rs: https://github.com/automata-network/dcap-rs/blob/main/src/types/mod.rs
    /// - EVM: https://github.com/automata-network/automata-dcap-attestation/blob/main/evm/contracts/types/CommonStruct.sol#L103-L120
    pub async fn get_verified_output(
        &self,
        verified_output_pubkey: Pubkey,
    ) -> anyhow::Result<VerifiedOutput> {
        let verified_output_account = self
            .program
            .account::<VerifiedOutputAccount>(verified_output_pubkey)
            .await?;

        let verified = verified_output_account.integrity_verified
            && verified_output_account.isv_signature_verified
            && verified_output_account.pck_cert_chain_verified
            && verified_output_account.fmspc_tcb_status != TcbStatus::Unspecified as u8
            && verified_output_account.qe_tcb_status != TcbStatus::Unspecified as u8;

        if !verified {
            return Err(anyhow::anyhow!("The output has not been fully verified"));
        }

        let fmspc_tcb_status =
            TcbStatus::try_from(verified_output_account.fmspc_tcb_status).unwrap();
        let tdx_module_tcb_status =
            TcbStatus::try_from(verified_output_account.tdx_module_tcb_status).unwrap();
        let qe_tcb_status = TcbStatus::try_from(verified_output_account.qe_tcb_status).unwrap();

        let quote_body = match verified_output_account.tee_type {
            SGX_TEE_TYPE => QuoteBody::SgxQuoteBody(
                EnclaveReportBody::try_from(
                    TryInto::<[u8; std::mem::size_of::<EnclaveReportBody>()]>::try_into(
                        verified_output_account.quote_body.clone(),
                    )
                    .unwrap(),
                )
                .unwrap(),
            ),
            TDX_TEE_TYPE => QuoteBody::Td10QuoteBody(
                Td10ReportBody::try_from(
                    TryInto::<[u8; std::mem::size_of::<Td10ReportBody>()]>::try_into(
                        verified_output_account.quote_body.clone(),
                    )
                    .unwrap(),
                )
                .unwrap(),
            ),
            _ => return Err(anyhow::anyhow!("unsupported tee type")),
        };

        let mut converged_tcb_status: TcbStatus = fmspc_tcb_status;
        if verified_output_account.tee_type == TDX_TEE_TYPE {
            converged_tcb_status = TcbInfo::converge_tcb_status_with_tdx_module(
                fmspc_tcb_status,
                tdx_module_tcb_status,
            );
        };

        converged_tcb_status =
            TcbInfo::converge_tcb_status_with_qe_tcb(converged_tcb_status, qe_tcb_status);

        // TEMP
        let quote_body_type: u16 = if verified_output_account.tee_type == SGX_TEE_TYPE {
            1
        } else {
            2
        };

        Ok(VerifiedOutput {
            quote_version: verified_output_account.quote_version,
            quote_body_type: quote_body_type,
            tcb_status: converged_tcb_status as u8,
            fmspc: verified_output_account.fmspc,
            quote_body: quote_body,
            advisory_ids: verified_output_account.advisory_ids,
        })
    }
}
