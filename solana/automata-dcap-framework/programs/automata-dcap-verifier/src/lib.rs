#![allow(unexpected_cfgs)]

pub mod errors;
pub mod instructions;
pub mod state;
pub mod utils;

use anchor_lang::prelude::*;
use errors::*;
use instructions::*;
use utils::certs::compute_output_digest_from_pem;
use utils::ecdsa::*;
use utils::zk::*;

declare_id!("FsmdtLRqiQt3jFdRfD4Goomz78LNtjthFqWuQt8rTKhC");

#[program]
pub mod automata_dcap_verifier {

    use anchor_lang::solana_program::{
        instruction::Instruction,
        program::invoke
    };
    use solana_zk_client::verify::{
        risc0::risc0_verify_instruction_data, succinct::sp1_groth16_verify_instruction_data,
    };
    use solana_zk_client::{RISC0_VERIFIER_ROUTER_ID, SUCCINCT_SP1_VERIFIER_ID};
    use zerocopy::AsBytes;

    use super::*;

    pub fn init_quote_buffer(
        ctx: Context<InitQuoteBuffer>,
        total_size: u32,
    ) -> Result<()> {
        let data_buffer = &mut ctx.accounts.data_buffer;

        data_buffer.owner = *ctx.accounts.owner.key;
        data_buffer.total_size = total_size;
        data_buffer.complete = false;
        data_buffer.data = vec![0; total_size as usize];

        msg!(
            "Quote buffer initialized with total size: {}",
            total_size
        );
        Ok(())
    }

    pub fn init_verified_output_account(ctx: Context<InitVerifiedOutput>) -> Result<()> {
        let verified_output = &mut ctx.accounts.verified_output;

        // Initialize the verified output account
        verified_output.owner = *ctx.accounts.owner.key;
        verified_output.quote_version = 0;
        verified_output.tee_type = 0;
        verified_output.tcb_status = String::new();
        verified_output.fmspc = [0; 6];
        verified_output.quote_body = Vec::new();
        verified_output.advisor_ids = None;
        verified_output.completed = false;

        msg!("Verified output account initialized");
        Ok(())
    }

    pub fn add_quote_chunk(
        ctx: Context<AddQuoteChunk>,
        chunk_data: Vec<u8>,
        offset: u32,
    ) -> Result<()> {
        let data_buffer = &mut ctx.accounts.data_buffer;

        require!(
            data_buffer.owner == *ctx.accounts.owner.key,
            DcapVerifierError::InvalidOwner
        );
        require!(
            !data_buffer.complete,
            DcapVerifierError::BufferAlreadyComplete
        );
        require!(
            (offset as usize + chunk_data.len()) as u32 <= data_buffer.total_size,
            DcapVerifierError::ChunkOutOfBounds
        );

        let start_index = offset as usize;
        let end_index = start_index + chunk_data.len();

        data_buffer.data[start_index..end_index].copy_from_slice(&chunk_data);
        data_buffer.complete = offset + chunk_data.len() as u32 == data_buffer.total_size;

        msg!(
            "Added chunk with offset {}, total bytes received until now: {}",
            offset,
            data_buffer.data.len()
        );
        Ok(())
    }

    pub fn verify_dcap_quote_integrity(ctx: Context<VerifyDcapQuoteIntegrity>) -> Result<()> {
        let data_buffer = &ctx.accounts.quote_data_buffer;
        let quote_data = &mut data_buffer.data.as_slice();

        let quote = Quote::read(quote_data).map_err(|e| {
            msg!("Error reading quote: {}", e);
            DcapVerifierError::InvalidQuote
        })?;

        // Extract the pck certificate pubkey and the qe report signature to verify
        let pem_chain = quote.signature.cert_data.cert_data;
        let pck_cert = load_first_cert_from_pem_data(&pem_chain).map_err(|e| {
            msg!("Error loading pck cert: {}", e);
            DcapVerifierError::InvalidQuote
        })?;
        let pck_pk_bytes = pck_cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .unwrap_or_default();

        let pck_pkey = VerifyingKey::from_sec1_bytes(pck_pk_bytes).unwrap();
        let compressed_pck_pkey = pck_pkey.to_encoded_point(true).to_bytes();

        let signature_bytes = quote.signature.qe_report_signature;
        let signature = Signature::from_slice(signature_bytes).unwrap();

        let normalized_siganture = match signature.normalize_s() {
            Some(s) => s.to_bytes(),
            None => signature.to_bytes()
        }.to_vec();

        let ix: Instruction = load_instruction_at_checked(0, &ctx.accounts.instructions_sysvar)?;
        verify_secp256r1_program_instruction_fields(
            &ix,
            &quote.signature.qe_report_body.as_bytes(),
            &compressed_pck_pkey,
            &normalized_siganture,
        )?;

        quote.signature.verify_qe_report().map_err(|e| {
            msg!("Error verifying quote's qe report: {}", e);
            DcapVerifierError::InvalidQuote
        })?;

        let verified_output = &mut ctx.accounts.verified_output;
        verified_output.integrity_verified = true;

        Ok(())
    }

    pub fn verify_dcap_quote_isv_signature(
        ctx: Context<VerifyDcapQuoteIsvSignature>,
    ) -> Result<()> {
        let data_buffer = &ctx.accounts.quote_data_buffer;
        let quote_data = &mut data_buffer.data.as_slice();

        let quote = Quote::read(quote_data).map_err(|e| {
            msg!("Error reading quote: {}", e);
            DcapVerifierError::InvalidQuote
        })?;

        // Extract the quote attestation key and signature to verify
        let unprefixed_attestation_key = quote.signature.attestation_pub_key;
        let mut prefixed_attestation_key: Vec<u8> = vec![0x04];
        prefixed_attestation_key.extend_from_slice(&unprefixed_attestation_key);
        let attestation_key = VerifyingKey::from_sec1_bytes(&prefixed_attestation_key)
            .unwrap();
        let compressed_attestation_key = attestation_key.to_encoded_point(true).to_bytes();

        let signature = Signature::from_slice(
            &quote.signature.isv_signature
        ).unwrap();

        let normalized_siganture = match signature.normalize_s() {
            Some(s) => s.to_bytes(),
            None => signature.to_bytes()
        }.to_vec();

        let header_bytes = quote.header.as_bytes();
        let body_bytes = quote.body.as_bytes();
        let mut data = Vec::with_capacity(header_bytes.len() + body_bytes.len());
        data.extend_from_slice(header_bytes);
        data.extend_from_slice(body_bytes);

        let ix: Instruction = load_instruction_at_checked(0, &ctx.accounts.instructions_sysvar)?;
        verify_secp256r1_program_instruction_fields(
            &ix,
            &data,
            &compressed_attestation_key,
            &normalized_siganture,
        )?;

        let verified_output = &mut ctx.accounts.verified_output;
        verified_output.isv_signature_verified = true;

        Ok(())
    }

    pub fn verify_dcap_quote_enclave_source(
        ctx: Context<VerifyDcapQuoteEnclaveSource>,
        _qe_type: String,
        _version: u8,
    ) -> Result<()> {
        let data_buffer = &ctx.accounts.quote_data_buffer;
        let quote_data = &mut data_buffer.data.as_slice();

        let quote = Quote::read(quote_data).map_err(|e| {
            msg!("Error reading quote: {}", e);
            DcapVerifierError::InvalidQuote
        })?;

        let enclave_identity = &ctx.accounts.qe_identity_pda.data;
        let enclave_identity: QuotingEnclaveIdentityAndSignature =
            serde_json::from_slice(enclave_identity).map_err(|e| {
                msg!("Error deserializing enclave identity: {}", e);
                DcapVerifierError::InvalidQuote
            })?;

        // TODO: We might need to change this once we atored the data in Borsh serialized form
        let qe_identity = enclave_identity.get_enclave_identity_bytes();
        let qe_identity: EnclaveIdentity = serde_json::from_slice(&qe_identity).map_err(|e| {
            msg!("Error deserializing enclave identity: {}", e);
            DcapVerifierError::InvalidQuote
        })?;

        if qe_identity.mrsigner != quote.signature.qe_report_body.mr_signer {
            msg!(
                "invalid qe mrsigner, expected {} but got {}",
                hex::encode(qe_identity.mrsigner),
                hex::encode(quote.signature.qe_report_body.mr_signer)
            );
            return Err(DcapVerifierError::InvalidQuote.into());
        }

        // Compare the isv_prod_id values
        if qe_identity.isvprodid != quote.signature.qe_report_body.isv_prod_id.get() {
            msg!(
                "invalid qe isv_prod_id, expected {} but got {}",
                qe_identity.isvprodid,
                quote.signature.qe_report_body.isv_prod_id.get()
            );
            return Err(DcapVerifierError::InvalidQuote.into());
        }

        // Compare the attribute values
        let qe_report_attributes = quote.signature.qe_report_body.sgx_attributes;
        let calculated_mask = qe_identity
            .attributes_mask
            .iter()
            .zip(qe_report_attributes.iter())
            .map(|(&mask, &attribute)| mask & attribute);

        if calculated_mask
            .zip(qe_identity.attributes)
            .any(|(masked, identity)| masked != identity)
        {
            msg!("qe attrtibutes mismatch");
            return Err(DcapVerifierError::InvalidQuote.into());
        }

        // Compare misc_select values
        let misc_select = quote.signature.qe_report_body.misc_select;
        let calculated_mask = qe_identity
            .miscselect_mask
            .as_bytes()
            .iter()
            .zip(misc_select.as_bytes().iter())
            .map(|(&mask, &attribute)| mask & attribute);

        if calculated_mask
            .zip(qe_identity.miscselect.as_bytes().iter())
            .any(|(masked, &identity)| masked != identity)
        {
            msg!("qe misc_select mismatch");
            return Err(DcapVerifierError::InvalidQuote.into());
        }

        let qe_tcb_status =
            qe_identity.get_qe_tcb_status(quote.signature.qe_report_body.isv_svn.get());
        let qe_tcb_status_pda = &mut ctx.accounts.qe_tcb_status_pda;
        qe_tcb_status_pda.status = serde_json::to_string(&qe_tcb_status).map_err(|e| {
            msg!("Error serializing qe tcb status: {}", e);
            DcapVerifierError::InvalidQuote
        })?;

        let verified_output = &mut ctx.accounts.verified_output;
        verified_output.enclave_source_verified = true;

        Ok(())
    }

    pub fn verify_pck_cert_chain_zk(
        ctx: Context<VerifyPckCertChainZk>,
        zkvm_selector: ZkvmSelector,
        proof_bytes: Vec<u8>,
    ) -> Result<()> {
        let data_buffer = &ctx.accounts.quote_data_buffer;
        let quote_data = &mut data_buffer.data.as_slice();

        let quote = Quote::read(quote_data).map_err(|e| {
            msg!("Error reading quote: {}", e);
            DcapVerifierError::InvalidQuote
        })?;

        // Step 1: Extract the PCK Certificate Chain from the quote data
        let pck_cert_chain_pem = quote.signature.cert_data.cert_data;

        // TODO: Check all certificates in the chain are unexpired and have not been revoked

        // Step 2: Compute the zkVM output data
        // the data consists of ABI-encoded of (bytes32, bytes32, bool) containing these values:
        // - the hash of the abi-encoded bytes array contains the PCK Certificate DER chain
        // - the hash of the root certificate DER
        // - true
        let output_digest: [u8; 32] = compute_output_digest_from_pem(pck_cert_chain_pem);

        // Step 3: make CPI to the Solana ZK Verifier program to verify proofs
        let x509_program_vkey = zkvm_selector
            .get_x509_verifier_program_vkey()
            .expect("Missing X509 Verifier program for the provided zkVM");

        // First, we get the instruction data and the zkvm verifier address
        let (zk_verify_instruction_data, zkvm_verifier_address) = match zkvm_selector {
            ZkvmSelector::RiscZero => (
                risc0_verify_instruction_data(&proof_bytes, *x509_program_vkey, output_digest),
                RISC0_VERIFIER_ROUTER_ID,
            ),
            ZkvmSelector::Succinct => (
                sp1_groth16_verify_instruction_data(
                    &proof_bytes,
                    *x509_program_vkey,
                    output_digest,
                ),
                SUCCINCT_SP1_VERIFIER_ID,
            ),
            _ => {
                return Err(DcapVerifierError::InvalidZkvmSelector.try_into().unwrap());
            },
        };

        // Check zkvm verifier program
        let zkvm_verifier_program = &ctx.accounts.zkvm_verifier_program;
        // require!(
        //     zkvm_verifier_program.key == &zkvm_verifier_address,
        //     DcapVerifierError::InvalidZkvmProgram
        // );

        // Create the context for the CPI call
        let verify_cpi_context = CpiContext::new(
            zkvm_verifier_program.to_account_info(),
            vec![ctx.accounts.system_program.to_account_info()],
        );

        // Invoke CPI to the zkvm verifier program
        invoke(
            &Instruction {
                program_id: zkvm_verifier_program.key().clone(),
                accounts: verify_cpi_context.to_account_metas(None),
                data: zk_verify_instruction_data
            },
            &[ctx.accounts.system_program.to_account_info()]
        )?;

        Ok(())
    }

    pub fn update_verified_output_account(
        ctx: Context<UpdateVerifiedOutput>,
        tcb_status: String,
        advisory_ids: Vec<String>,
        fmspc: [u8; 6],
    ) -> Result<()> {
        let data_buffer = &ctx.accounts.quote_data_buffer;
        let quote = Quote::read(&mut data_buffer.data.as_slice()).map_err(|e| {
            msg!("Error reading quote: {}", e);
            DcapVerifierError::InvalidQuote
        })?;

        let pck_extension = quote.signature.get_pck_extension().map_err(|e| {
            msg!("Error getting pck extension: {}", e);
            DcapVerifierError::InvalidSgxPckExtension
        })?;

        let tcb_info = &ctx.accounts.tcb_info_pda;
        msg!("tcb info len: {}", tcb_info.data.len());
        let _tcb_info = TcbInfo::from_bytes(tcb_info.data.as_slice()).map_err(|e| {
            msg!("Error deserializing tcb info: {}", e);
            DcapVerifierError::SerializationError
        })?;

        let (sgx_tcb_status, tdx_tcb_status, advisory_ids) = verify_tcb_status(&_tcb_info, &pck_extension, &quote).map_err(|e| {
            msg!("Error verifying tcb status: {}", e);
            DcapVerifierError::UnsuccessfulTcbStatusVerification
        })?;


        let mut tcb_status;
        if quote.header.tee_type == TDX_TEE_TYPE {
            let tdx_module_status = _tcb_info.verify_tdx_module(quote.body.as_tdx_report_body().unwrap()).map_err(|e| {
                msg!("Error verifying tdx module: {}", e);
                DcapVerifierError::InvalidQuote
            })?;
            tcb_status = TcbInfo::converge_tcb_status_with_tdx_module(tdx_tcb_status, tdx_module_status);
        } else {
            tcb_status = sgx_tcb_status;
        }

        let qe_tcb_status_pda = &mut ctx.accounts.qe_tcb_status_pda;
        let qe_tcb_status = serde_json::from_str(&qe_tcb_status_pda.status).map_err(|e| {
            msg!("Error deserializing qe tcb status: {}", e);
            DcapVerifierError::SerializationError
        })?;

        tcb_status = TcbInfo::converge_tcb_status_with_qe_tcb(tcb_status, qe_tcb_status);

        let verified_output = &mut ctx.accounts.verified_output;
        verified_output.tcb_status = serde_json::to_string(&tcb_status).map_err(|e| {
            msg!("Error serializing tcb status: {}", e);
            DcapVerifierError::SerializationError
        })?;

        verified_output.advisor_ids = Some(advisory_ids);
        verified_output.fmspc = fmspc;
        verified_output.quote_version = quote.header.version.get();
        verified_output.tee_type = quote.header.tee_type;
        verified_output.quote_body = quote.body.as_bytes().to_vec();
        verified_output.completed = verified_output.integrity_verified && verified_output.isv_signature_verified
            && verified_output.enclave_source_verified
            && verified_output.tcb_check_verified
            && verified_output.pck_cert_chain_verified;


        Ok(())
    }
}
