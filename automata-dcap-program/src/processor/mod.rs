mod risc0;
use risc0::{DCAP_IMAGE_ID, RISCZERO_GROTH16_VERIFY_INSTRUCTION_DISCRIMINATOR};

mod sp1;
use sp1::SP1Groth16Proof;

use crate::{
    error::DcapProgramError, instruction::ProgramInstruction, state::*, DCAP_COUNTER_ADDR,
    RISC0_GROTH16_VERIFIER_ADDR, SP1_DCAP_GROTH16_VERIFIER_ADDR
};
use borsh::{BorshDeserialize, BorshSerialize};
use sha2::{Digest, Sha256};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    msg,
    program::{invoke, invoke_signed},
    program_error::ProgramError,
    program_memory::sol_memcmp,
    pubkey::{Pubkey, PUBKEY_BYTES},
    system_instruction::create_account,
    system_program,
    sysvar::{rent, Sysvar}
};

pub fn process(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction: ProgramInstruction,
) -> ProgramResult {
    match instruction {
        ProgramInstruction::CreateDcapOutputAccount {
            close_authority,
            verified_output,
        } => {
            process_create_output_account(program_id, accounts, &close_authority, &verified_output)
        }
        ProgramInstruction::VerifyDcapProof {
            zkvm_selector,
            proof_bytes,
        } => process_verify_dcap_proof(program_id, accounts, zkvm_selector, &proof_bytes),
        ProgramInstruction::DeleteDcapOutputAccount(output_id) => {
            process_delete_output_account(program_id, accounts, &output_id)
        }
    }
}

fn process_create_output_account(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    close_authority: &Pubkey,
    verified_output: &[u8],
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();

    // check for required signers
    let payer_account_info = next_account_info(account_info_iter)?;
    let payer = payer_account_info
        .signer_key()
        .ok_or(ProgramError::from(DcapProgramError::MissingRequiredSigner))?;

    // load current count
    let counter_account_info = next_account_info(account_info_iter)?;
    if counter_account_info.unsigned_key() != &Pubkey::from_str_const(DCAP_COUNTER_ADDR) {
        return Err(ProgramError::from(DcapProgramError::AccountMismatch));
    }
    check_account_owner(program_id, counter_account_info)?;
    let counter_account_info_data = &mut counter_account_info.data.borrow_mut()[..];
    let mut counter_account_info_state =
        match CounterAccountData::try_from_slice(counter_account_info_data) {
            Ok(ret) => ret,
            Err(_) => {
                return Err(ProgramError::from(DcapProgramError::InvalidAccountData));
            }
        };

    // check PDA derivation
    let output_pda_account_info = next_account_info(account_info_iter)?;
    let seeds: &[&[u8]] = &[b"automata-dcap", &counter_account_info_data];
    let (derived_pda, bump_seed) = Pubkey::find_program_address(seeds, program_id);
    if output_pda_account_info.unsigned_key() != &derived_pda {
        return Err(ProgramError::from(DcapProgramError::AccountMismatch));
    }

    // PDA data
    let output_account_state = OutputAccountData {
        close_authority: *close_authority,
        output: verified_output.to_vec(),
        verified: false,
    };
    let mut output_account_serialized_data: Vec<u8> = vec![];
    output_account_state.serialize(&mut output_account_serialized_data)?;

    // check on-chain native programs and calculate rent
    let system_program_account_info = next_account_info(account_info_iter)?;
    let system_program_id = system_program_account_info.unsigned_key();
    if !system_program::check_id(system_program_id) {
        return Err(ProgramError::IncorrectProgramId);
    }
    let rent_program_id = next_account_info(account_info_iter)?.unsigned_key();
    if !rent::check_id(rent_program_id) {
        return Err(ProgramError::IncorrectProgramId);
    }
    let rent = rent::Rent::get()?;
    let space = output_account_serialized_data.len();
    let rent_exempt_lamports = rent.minimum_balance(space);

    // Create the PDA
    let create_pda_instruction = create_account(
        payer,
        &derived_pda,
        rent_exempt_lamports,
        space as u64,
        program_id,
    );
    invoke_signed(
        &create_pda_instruction,
        &[
            payer_account_info.clone(),
            output_pda_account_info.clone(),
            system_program_account_info.clone(),
        ],
        &[&[b"automata-dcap", &counter_account_info_data, &[bump_seed]]],
    )?;

    // write the data to the PDA
    let output_account_info_data = &mut output_pda_account_info.data.borrow_mut()[..];
    output_account_info_data.copy_from_slice(&output_account_serialized_data);

    // Log the current index number for the PDA
    msg!("ID: {}", counter_account_info_state.current_count());

    // increment and write to counter
    counter_account_info_state.increment();
    borsh::to_writer(counter_account_info_data, &counter_account_info_state)?;

    Ok(())
}

fn process_verify_dcap_proof(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    zkvm_selector: u8,
    proof_bytes: &[u8],
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let output_account_info = next_account_info(account_info_iter)?;

    // check the pda account owner
    check_account_owner(program_id, output_account_info)?;

    // check the account data
    if output_account_info.data_is_empty() {
        return Err(ProgramError::UninitializedAccount);
    }

    let output_account_info_data = &mut output_account_info.data.borrow_mut()[..];
    let mut output_account_info_state =
        match OutputAccountData::try_from_slice(output_account_info_data) {
            Ok(ret) => ret,
            Err(_) => {
                return Err(ProgramError::from(DcapProgramError::InvalidAccountData));
            }
        };

    if !output_account_info_state.verified {
        // pre-process the data before invoking the Verifier program
        let output_data = output_account_info_state.output.as_slice();
        let output_data_digest = Sha256::digest(output_data).to_vec();;
        let verifier_pubkey;
        let verifier_instruction_data = match zkvm_selector {
            1 => {
                // RiscZero
                verifier_pubkey = Pubkey::from_str_const(RISC0_GROTH16_VERIFIER_ADDR);
                [
                    RISCZERO_GROTH16_VERIFY_INSTRUCTION_DISCRIMINATOR.to_vec(),
                    proof_bytes.to_vec(),
                    DCAP_IMAGE_ID.to_vec(),
                    output_data_digest,
                ]
                .concat()
            }
            2 => {
                // SP1
                verifier_pubkey = Pubkey::from_str_const(SP1_DCAP_GROTH16_VERIFIER_ADDR);
                let sp1_groth16_proof = SP1Groth16Proof {
                    proof: proof_bytes.to_vec(),
                    sp1_public_inputs_hash: output_data_digest,
                };
                let mut ret: Vec<u8> = vec![];
                sp1_groth16_proof.serialize(&mut ret)?;
                ret
            }
            _ => {
                return Err(ProgramError::from(DcapProgramError::UnknownZkVm));
            }
        };

        // invoke the verifier program to verify proofs
        let verifier_program_account = next_account_info(account_info_iter)?;
        if verifier_program_account.unsigned_key() != &verifier_pubkey {
            return Err(ProgramError::from(DcapProgramError::AccountMismatch));
        }

        // check system program address (required by RiscZero Verifier because of Anchor)
        let system_program_account_info = next_account_info(account_info_iter)?;
        let system_program_id = system_program_account_info.unsigned_key();
        if !system_program::check_id(system_program_id) {
            return Err(ProgramError::IncorrectProgramId);
        }

        let verify_instruction = Instruction::new_with_bytes(
            verifier_pubkey,
            verifier_instruction_data.as_slice(),
            vec![AccountMeta::new_readonly(system_program_id.clone(), false)],
        );
        if invoke(&verify_instruction, &[system_program_account_info.clone()]).is_err() {
            return Err(ProgramError::from(
                DcapProgramError::ProofVerificationFailure,
            ));
        }

        // update the OutputAccount state
        output_account_info_state.verified = true;
        borsh::to_writer(output_account_info_data, &output_account_info_state)?;
    }

    Ok(())
}

fn process_delete_output_account(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    output_id: &[u8],
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();

    // check for required signers
    let signer_account_info = next_account_info(account_info_iter)?;
    let signer_pubkey = signer_account_info
        .signer_key()
        .ok_or(ProgramError::from(DcapProgramError::MissingRequiredSigner))?;

    let output_pda_account_info = next_account_info(account_info_iter)?;

    // check the pda account owner
    check_account_owner(program_id, output_pda_account_info)?;

    // check PDA derivation
    // we don't need to check whether data is empty or not
    // because you cannot have a valid PDA owner with empty data
    let seeds: &[&[u8]] = &[b"automata-dcap", output_id];
    let (derived_pda, _) = Pubkey::find_program_address(seeds, program_id);
    if output_pda_account_info.unsigned_key() != &derived_pda {
        return Err(ProgramError::from(DcapProgramError::AccountMismatch));
    }

    {
        // scoped to drop references to output_account_info after checking authority...

        let output_account_info_data = &output_pda_account_info.data.borrow()[..];
        let output_account_info_state =
            match OutputAccountData::try_from_slice(output_account_info_data) {
                Ok(ret) => ret,
                Err(_) => {
                    return Err(ProgramError::from(DcapProgramError::InvalidAccountData));
                }
            };

        // check signer matches with authority pubkey
        if signer_pubkey != &output_account_info_state.close_authority {
            return Err(ProgramError::IncorrectAuthority);
        }
    }

    // check system program address
    let system_program_account_info = next_account_info(account_info_iter)?;
    let system_program_id = system_program_account_info.unsigned_key();
    if !system_program::check_id(system_program_id) {
        return Err(ProgramError::IncorrectProgramId);
    }

    // close the account
    // https://solana.com/developers/cookbook/accounts/close-account
    let pda_lamports = output_pda_account_info.lamports();
    let signer_lamports = signer_account_info.lamports();
    **signer_account_info.lamports.borrow_mut() =
        signer_lamports.checked_add(pda_lamports).unwrap();
    **output_pda_account_info.lamports.borrow_mut() = 0;

    output_pda_account_info.assign(system_program_id);
    output_pda_account_info.realloc(0, false)?;

    Ok(())
}

fn check_account_owner(program_id: &Pubkey, account_info: &AccountInfo) -> ProgramResult {
    let equal = sol_memcmp(
        program_id.as_ref(),
        account_info.owner.as_ref(),
        PUBKEY_BYTES,
    ) == 0;
    if !equal {
        Err(ProgramError::from(DcapProgramError::InvalidAccountOwner))
    } else {
        Ok(())
    }
}
