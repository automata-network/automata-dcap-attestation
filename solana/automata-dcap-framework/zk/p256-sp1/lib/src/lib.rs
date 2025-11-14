#[cfg(test)]
mod tests;

use anyhow::Result;
use dcap_p256_zk_lib::client::serialize_input;
use dcap_p256_zk_lib::InputType;
use sp1_sdk::{HashableKey, ProverClient, SP1Stdin, include_elf};

pub const PROGRAM_ELF: &[u8] = include_elf!("dcap-p256-sp1-program");

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum ProofType {
    Mock,
    Groth16,
    Plonk,
}

pub fn get_proof(
    proof_option: ProofType,
    input_type: InputType,
    subject_data: Vec<u8>,
    issuer_raw_der: Vec<u8>,
) -> Result<(
    [u8; 32], // vkey
    Vec<u8>,  // output bytes
    Vec<u8>,  // proof bytes
)> {
    // serialize the input
    let input_bytes = serialize_input(input_type, subject_data, issuer_raw_der);

    // prepare the zkVM input
    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&input_bytes);

    let client = ProverClient::from_env();

    // execute the zkVM program
    let (output, report) = client.execute(PROGRAM_ELF, &stdin).run()?;

    println!(
        "executed program with {} cycles",
        report.total_instruction_count()
    );

    let (pk, vk) = client.setup(PROGRAM_ELF);
    println!("program vkey: {}", vk.bytes32());

    let proof = match proof_option {
        ProofType::Groth16 => client.prove(&pk, &stdin).groth16().run()?.bytes(),
        ProofType::Plonk => client.prove(&pk, &stdin).plonk().run()?.bytes(),
        _ => vec![],
    };

    Ok((vk.bytes32_raw(), output.to_vec(), proof))
}

pub fn get_program_vkey() -> [u8; 32] {
    let client = ProverClient::from_env();
    let (_, vk) = client.setup(PROGRAM_ELF);
    vk.bytes32_raw()
}