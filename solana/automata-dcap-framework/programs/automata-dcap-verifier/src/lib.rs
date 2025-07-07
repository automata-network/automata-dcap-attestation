#![allow(unexpected_cfgs)]

pub mod errors;
pub mod instructions;
pub mod state;
pub mod utils;

use aligned_vec::AVec;
use anchor_lang::prelude::*;
use errors::*;
use instructions::*;
use p256::ecdsa::Signature;
use p256::ecdsa::VerifyingKey;
use utils::ecdsa::*;

use anchor_lang::solana_program::sysvar::instructions::load_instruction_at_checked;
use anchor_lang::solana_program::{instruction::Instruction, program::invoke};
use dcap_rs::types::quote::{Quote, QuoteBody, SGX_TEE_TYPE, TDX_TEE_TYPE};
use zerocopy::AsBytes;

use programs_shared::certs::*;
use programs_shared::crl::*;
use programs_shared::zk::ZkvmSelector;
use programs_shared::x509_parser::parse_x509_certificate;
use programs_shared::get_cn_from_x509_name;

declare_id!("FsmdtLRqiQt3jFdRfD4Goomz78LNtjthFqWuQt8rTKhC");

#[program]
pub mod automata_dcap_verifier {
    use super::*;

    pub fn create_quote_accounts(ctx: Context<Create>, quote_size: u32) -> Result<()> {
        let quote_buffer_account = &mut ctx.accounts.quote_data_buffer;

        // Initialize the quote buffer account
        quote_buffer_account.owner = *ctx.accounts.owner.key;
        quote_buffer_account.total_size = quote_size;
        quote_buffer_account.data = vec![0u8; quote_size as usize];

        // Set all tcb statuses to 7 (Unspecified)
        let verified_output = &mut ctx.accounts.verified_output;
        verified_output.fmspc_tcb_status = 7u8;
        verified_output.tdx_module_tcb_status = 7u8;
        verified_output.qe_tcb_status = 7u8;

        msg!(
            "Created quote buffer account with size {} bytes",
            quote_size
        );

        Ok(())
    }

    pub fn add_quote_chunk(
        ctx: Context<AddQuoteChunk>,
        chunk_data: Vec<u8>,
        offset: u32,
    ) -> Result<()> {
        let data_buffer = &mut ctx.accounts.data_buffer;

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
        use dcap_rs::utils::cert_chain_processor::load_first_cert_from_pem_data;

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
            None => signature.to_bytes(),
        }
        .to_vec();

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
        verified_output.quote_version = quote.header.version.get();
        verified_output.tee_type = quote.header.tee_type;
        verified_output.quote_body = quote.body.as_bytes().to_vec();
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
        let attestation_key = VerifyingKey::from_sec1_bytes(&prefixed_attestation_key).unwrap();
        let compressed_attestation_key = attestation_key.to_encoded_point(true).to_bytes();

        let signature = Signature::from_slice(&quote.signature.isv_signature).unwrap();

        let normalized_siganture = match signature.normalize_s() {
            Some(s) => s.to_bytes(),
            None => signature.to_bytes(),
        }
        .to_vec();

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
        use dcap_rs::types::pod::enclave_identity::zero_copy::*;

        let data_buffer = &ctx.accounts.quote_data_buffer;
        let quote_data = &mut data_buffer.data.as_slice();

        let quote = Quote::read(quote_data).map_err(|e| {
            msg!("Error reading quote: {}", e);
            DcapVerifierError::InvalidQuote
        })?;

        let now = Clock::get().unwrap().unix_timestamp;
        let qe_identity_validity = now >= ctx.accounts.qe_identity_pda.issue_timestamp
            && now <= ctx.accounts.qe_identity_pda.next_update_timestamp;
        if !qe_identity_validity {
            msg!("QE Identity has expired");
            return Err(DcapVerifierError::ExpiredCollateral.into());
        }

        // TEMP: Using **owned** data for now by copying and aligned the data into heap,
        // because if I simply "borrow" the data, we would run into alignment issues upon de-serialization
        // AFAIK, the serialized QEIdentity data should not exceed the Solana 32kb heap limit
        let qe_identity_data_may_be_unaligned = &ctx.accounts.qe_identity_pda.data;

        let qe_identity_data_owned: Option<AVec<u8>>;
        let qe_identity_data = if qe_identity_data_may_be_unaligned.as_ptr().align_offset(8) == 0 {
            // The data is already aligned, so we can use it directly
            qe_identity_data_may_be_unaligned.as_slice()
        } else {
            // The data is not aligned, so we need to copy it into an aligned vector
            let mut buff: AVec<u8> =
                AVec::with_capacity(8, qe_identity_data_may_be_unaligned.len());
            buff.extend_from_slice(qe_identity_data_may_be_unaligned);
            qe_identity_data_owned = Some(buff);
            qe_identity_data_owned.as_ref().unwrap().as_slice()
        };

        let qe_identity =
            EnclaveIdentityZeroCopy::from_bytes(&qe_identity_data[64..]).map_err(|e| {
                msg!("Error deserializing qe identity: {}", e);
                DcapVerifierError::SerializationError
            })?;

        if qe_identity.mrsigner_bytes() != quote.signature.qe_report_body.mr_signer {
            msg!(
                "invalid qe mrsigner, expected {} but got {}",
                hex::encode(qe_identity.mrsigner_bytes()),
                hex::encode(quote.signature.qe_report_body.mr_signer)
            );
            return Err(DcapVerifierError::InvalidQuote.into());
        }

        // Compare the isv_prod_id values
        if qe_identity.isvprodid() != quote.signature.qe_report_body.isv_prod_id.get() {
            msg!(
                "invalid qe isv_prod_id, expected {} but got {}",
                qe_identity.isvprodid(),
                quote.signature.qe_report_body.isv_prod_id.get()
            );
            return Err(DcapVerifierError::InvalidQuote.into());
        }

        // Compare the attribute values
        let qe_report_attributes = quote.signature.qe_report_body.sgx_attributes;
        let qe_identity_attributes_mask = qe_identity.attributes_mask_bytes();
        let calculated_mask = qe_identity_attributes_mask
            .iter()
            .zip(qe_report_attributes.iter())
            .map(|(&mask, &attribute)| mask & attribute);

        if calculated_mask
            .zip(qe_identity.attributes_bytes())
            .any(|(masked, identity)| masked != identity)
        {
            msg!("qe attrtibutes mismatch");
            return Err(DcapVerifierError::InvalidQuote.into());
        }

        // Compare misc_select values
        let misc_select = quote.signature.qe_report_body.misc_select;
        let qe_identity_miscselect_mask = qe_identity.miscselect_mask_bytes();
        let calculated_mask = qe_identity_miscselect_mask
            .iter()
            .zip(misc_select.as_bytes().iter())
            .map(|(&mask, &attribute)| mask & attribute);

        if calculated_mask
            .zip(qe_identity.miscselect_bytes().iter())
            .any(|(masked, &identity)| masked != identity)
        {
            msg!("qe misc_select mismatch");
            return Err(DcapVerifierError::InvalidQuote.into());
        }

        let quote_isvsvn = quote.signature.qe_report_body.isv_svn.get();
        let qe_tcb_status = qe_identity
            .tcb_levels()
            .filter_map(|qe_tcb| qe_tcb.ok())
            .find(|qe_tcb| quote_isvsvn >= qe_tcb.isvsvn())
            .map(|qe_tcb| qe_tcb.tcb_status_byte())
            .unwrap_or(7); // Default "Unspecified" status value if no matching TCB level found

        let verified_output = &mut ctx.accounts.verified_output;
        verified_output.qe_tcb_status = qe_tcb_status;

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

        // TODO: pick a certificate from the given index and its issuer

        // // Step 3: Validate each certificate in the chain
        // let now = Clock::get().unwrap().unix_timestamp;
        // for (i, cert) in cert_chain.iter().enumerate() {
        //     let (_, x509) = parse_x509_certificate(cert).unwrap();
        //     let tbs = &x509.tbs_certificate;
            
        //     // First, check the validity range for each certificate
        //     let (not_before, not_after) = get_certificate_validity(tbs);
        //     let serial_nuber = get_certificate_serial(tbs);

        //     let cert_validity = now >= not_before && now <= not_after;
        //     if !cert_validity {
        //         msg!("Certificate {} has expired", i);
        //         return Err(DcapVerifierError::ExpiredCollateral.into());
        //     }

        //     // Then, check the revocation status for PCK and PCK Issuer Certificate
        //     // For the root certificate, we just have to make sure that the pubkey matches
        //     // with what is expected
        //     if i == 0 {
        //         let pck_crl_account = &ctx.accounts.pck_crl;

        //         // Check PCK CRL account is valid
        //         let pck_ca_type_str = get_cn_from_x509_name(tbs.issuer()).unwrap();
        //         let (expected_pck_crl_pubkey, _) = Pubkey::find_program_address(
        //             &[b"pcs_cert", pck_ca_type_str.as_bytes(), &[true as u8]],
        //             &automata_on_chain_pccs::ID,
        //         );

        //         if expected_pck_crl_pubkey != pck_crl_account.key() {
        //             msg!("Invalid PCK CRL account");
        //             return Err(DcapVerifierError::MismatchPda.into());
        //         }

        //         if check_certificate_revocation(&serial_nuber, &pck_crl_account.cert_data).is_err() {
        //             msg!("PCK Certificate revoked");
        //             return Err(DcapVerifierError::RevokedCertificate.into());
        //         }
        //     } else if i == 1 {
        //         let root_crl_account = &ctx.accounts.root_crl;

        //         if check_certificate_revocation(&serial_nuber, &root_crl_account.cert_data).is_err() {
        //             msg!("PCK Intermediate Certificate revoked");
        //             return Err(DcapVerifierError::RevokedCertificate.into());
        //         }
        //     } else {
        //         let root_pubkey = tbs.public_key().subject_public_key.as_ref();
        //         require!(
        //             root_pubkey == INTEL_ROOT_PUB_KEY,
        //             DcapVerifierError::InvalidRootCa
        //         );
        //     }
        // }

        // // First, we get the instruction data and the zkvm verifier address
        // let (zk_verify_instruction_data, zkvm_verifier_address) = match zkvm_selector {
        //     ZkvmSelector::RiscZero => (
        //         risc0_verify_instruction_data(&proof_bytes, *x509_program_vkey, output_digest),
        //         RISC0_VERIFIER_ROUTER_ID,
        //     ),
        //     ZkvmSelector::Succinct => (
        //         sp1_groth16_verify_instruction_data(
        //             &proof_bytes,
        //             *x509_program_vkey,
        //             output_digest,
        //         ),
        //         SUCCINCT_SP1_VERIFIER_ID,
        //     ),
        //     _ => {
        //         return Err(DcapVerifierError::InvalidZkvmSelector.try_into().unwrap());
        //     },
        // };

        // // Check zkvm verifier program
        // let zkvm_verifier_program = &ctx.accounts.zkvm_verifier_program;
        // // require!(
        // //     zkvm_verifier_program.key == &zkvm_verifier_address,
        // //     DcapVerifierError::InvalidZkvmProgram
        // // );

        // // Create the context for the CPI call
        // let verify_cpi_context = CpiContext::new(
        //     zkvm_verifier_program.to_account_info(),
        //     vec![ctx.accounts.system_program.to_account_info()],
        // );

        // // Invoke CPI to the zkvm verifier program
        // invoke(
        //     &Instruction {
        //         program_id: zkvm_verifier_program.key().clone(),
        //         accounts: verify_cpi_context.to_account_metas(None),
        //         data: zk_verify_instruction_data,
        //     },
        //     &[ctx.accounts.system_program.to_account_info()],
        // )?;

        let verified_output = &mut ctx.accounts.verified_output;
        verified_output.pck_cert_chain_verified = true;

        Ok(())
    }

    pub fn verify_dcap_quote_tcb_status(
        ctx: Context<VerifyDcapQuoteTcbStatus>,
        _tcb_type: String,
        _version: u8,
        fmspc: [u8; 6],
    ) -> Result<()> {
        use dcap_rs::types::pod::tcb_info::zero_copy::utils::*;
        use dcap_rs::types::pod::tcb_info::zero_copy::*;

        let data_buffer = &ctx.accounts.quote_data_buffer;
        let quote = Quote::read(&mut data_buffer.data.as_slice()).map_err(|e| {
            msg!("Error reading quote: {}", e);
            DcapVerifierError::InvalidQuote
        })?;

        let pck_extension = quote.signature.get_pck_extension().map_err(|e| {
            msg!("Error getting pck extension: {}", e);
            DcapVerifierError::InvalidSgxPckExtension
        })?;

        let now = Clock::get().unwrap().unix_timestamp;
        let tcb_info_is_valid = now >= ctx.accounts.tcb_info_pda.issue_timestamp
            && now <= ctx.accounts.tcb_info_pda.next_update_timestamp;
        if !tcb_info_is_valid {
            msg!("TCB Info has expired");
            return Err(DcapVerifierError::ExpiredCollateral.into());
        }

        let tcb_info_data_may_be_unaligned = &ctx.accounts.tcb_info_pda.data;

        // TEMP: Using **owned** data for now by copying and aligned the data into heap,
        // because if I simply "borrow" the data, we would run into alignment issues upon de-serialization
        // AFAIK, the serialized TCBInfo data should not exceed the Solana 32kb heap limit
        let tcb_info_data_owned: Option<AVec<u8>>;
        let tcb_info_data = if tcb_info_data_may_be_unaligned.as_ptr().align_offset(8) == 0 {
            // The data is already aligned, so we can use it directly
            tcb_info_data_may_be_unaligned.as_slice()
        } else {
            // The data is not aligned, so we need to copy it into an aligned vector
            let mut buff: AVec<u8> = AVec::with_capacity(8, tcb_info_data_may_be_unaligned.len());
            buff.extend_from_slice(tcb_info_data_may_be_unaligned);
            tcb_info_data_owned = Some(buff);
            tcb_info_data_owned.as_ref().unwrap().as_slice()
        };

        let tcb_info = TcbInfoZeroCopy::from_bytes(&tcb_info_data[64..]).map_err(|e| {
            msg!("Error deserializing tcb info: {}", e);
            DcapVerifierError::SerializationError
        })?;

        // Step 1: FMSPC check
        if pck_extension.fmspc != fmspc {
            msg!(
                "FMSPC mismatch, expected {} but got {}",
                hex::encode(fmspc),
                hex::encode(pck_extension.fmspc)
            );
            return Err(DcapVerifierError::MismatchFmspc.into());
        }

        // Step 2: PCEID check
        let tcb_info_pceid: [u8; 2] = tcb_info.pce_id();
        if pck_extension.pceid != tcb_info_pceid {
            msg!(
                "PCEID mismatch, expected {} but got {}",
                hex::encode(tcb_info_pceid),
                hex::encode(pck_extension.pceid)
            );
            return Err(DcapVerifierError::MismatchPceid.into());
        }

        // Step 3: Perform a lookup to fetch the matching TCB level from the TCB info
        let (raw_sgx_tcb_status, raw_tdx_tcb_status, advisory_ids) =
            lookup(&pck_extension, &tcb_info, &quote).unwrap();

        let verified_output = &mut ctx.accounts.verified_output;

        verified_output.fmspc = fmspc;

        let fmspc_tcb_status = match quote.header.tee_type {
            SGX_TEE_TYPE => raw_sgx_tcb_status,
            TDX_TEE_TYPE => raw_tdx_tcb_status,
            _ => {
                msg!("Unsupported TEE type");
                return Err(DcapVerifierError::InvalidQuote.into());
            },
        };
        verified_output.fmspc_tcb_status = fmspc_tcb_status;

        // If a TDX quote is provided, we need to look up the TDX module TCB status as well
        if let QuoteBody::Td10QuoteBody(quote_body) = quote.body {
            let (tdx_module_isv_svn, tdx_module_version) =
                (quote_body.tee_tcb_svn[0], quote_body.tee_tcb_svn[1]);

            let mrsigner_seam = quote_body.mr_signer_seam;
            let seam_attributes = quote_body.seam_attributes;

            let tdx_module = if let Some(tdx_module) = tcb_info.tdx_module() {
                tdx_module
            } else {
                msg!("Missing TDX module");
                return Err(DcapVerifierError::MissingTdxModule.into());
            };

            let raw_tdx_module_tcb = if tdx_module_version == 0 {
                let tdx_module_mrsigner: [u8; 48] = tdx_module.mrsigner();
                let tdx_module_attributes: [u8; 8] = tdx_module.attributes();
                if mrsigner_seam != tdx_module_mrsigner {
                    msg!("Mismatch mrsigner seam");
                    return Err(DcapVerifierError::MismatchMrsignerSeam.into());
                }
                if seam_attributes != tdx_module_attributes {
                    msg!("Mismatch seam attributes");
                    return Err(DcapVerifierError::MismatchSeamAttribute.into());
                }
                0u8
            } else {
                if tcb_info.tdx_module_identities_count() == 0 {
                    msg!("Missing TDX module identities");
                    return Err(DcapVerifierError::MissingTdxModuleIdentities.into());
                }

                let id_string = format!("TDX_{:02x}", tdx_module_version);
                let mut tcb_status = verified_output.tdx_module_tcb_status;

                let tdx_module_identities_iter = tcb_info.tdx_module_identities();
                for tdx_module_identity in tdx_module_identities_iter {
                    let tdx_module_identity = tdx_module_identity.unwrap();
                    if tdx_module_identity.id_str().unwrap() == id_string.as_str() {
                        let mut tcb_matched = false;
                        let tdx_tcb_levels_iter = tdx_module_identity.tcb_levels();
                        for tdx_tcb_level in tdx_tcb_levels_iter {
                            let tdx_tcb_level = tdx_tcb_level.unwrap();
                            if tdx_module_isv_svn >= tdx_tcb_level.tcb_isvsvn() {
                                let tdx_module_mrsigner: [u8; 48] = tdx_module_identity.mrsigner();
                                let tdx_module_attributes: [u8; 8] =
                                    tdx_module_identity.attributes();
                                if mrsigner_seam != tdx_module_mrsigner {
                                    msg!("Mismatch mrsigner seam");
                                    return Err(DcapVerifierError::MismatchMrsignerSeam.into());
                                }
                                if seam_attributes != tdx_module_attributes {
                                    msg!("Mismatch seam attributes");
                                    return Err(DcapVerifierError::MismatchSeamAttribute.into());
                                }
                                tcb_status = tdx_tcb_level.tcb_status();
                                tcb_matched = true;
                                break;
                            }
                        }
                        if tcb_matched {
                            break;
                        }
                    }
                }

                tcb_status
            };

            verified_output.tdx_module_tcb_status = raw_tdx_module_tcb;
        }

        // Return the advisory IDs if any
        if !advisory_ids.is_empty() {
            verified_output.advisory_ids = Some(advisory_ids);
        }

        Ok(())
    }

    pub fn close_quote_accounts(ctx: Context<CloseQuoteBuffer>) -> Result<()> {
        msg!(
            "Closed quote buffer account: {}",
            ctx.accounts.quote_data_buffer.key()
        );
        msg!(
            "Closed verified output account: {}",
            ctx.accounts.verified_output.key()
        );
        Ok(())
    }
}
