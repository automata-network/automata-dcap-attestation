use anyhow::Result;
use borsh::BorshDeserialize;
use solana_program::{program_error::ProgramError, pubkey::Pubkey};

#[derive(Debug)]
pub enum ProgramInstruction {
    CreateDcapOutputAccount {
        close_authority: Pubkey,
        verified_output: Vec<u8>,
    },
    VerifyDcapProof {
        zkvm_selector: u8,
        proof_bytes: Vec<u8>,
    },
    DeleteDcapOutputAccount([u8; 8])
}

impl ProgramInstruction {
    pub fn unpack(instruction_data: &[u8]) -> Result<Self> {
        let (&tag, mut data) = instruction_data
            .split_first()
            .ok_or(ProgramError::InvalidInstructionData)?;

        let instruction = match tag {
            0 => {
                let (close_authority, verified_output) =
                    <(Pubkey, Vec<u8>)>::deserialize(&mut data)?;
                Self::CreateDcapOutputAccount {
                    close_authority,
                    verified_output,
                }
            }
            1 => {
                let (zkvm_selector, proof_bytes) = <(u8, Vec<u8>)>::deserialize(&mut data)?;
                Self::VerifyDcapProof {
                    zkvm_selector,
                    proof_bytes,
                }
            }
            2 => {
                let output_id = data[..8].try_into()?;
                Self::DeleteDcapOutputAccount(output_id)
            },
            _ => {
                return Err(ProgramError::InvalidInstructionData.into());
            }
        };

        Ok(instruction)
    }
}
