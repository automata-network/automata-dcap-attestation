// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use dcap_p256_zk_lib::Input;
use dcap_p256_zk_lib::verify::verify_input;

use borsh::BorshDeserialize;

pub fn main() {
    // Read the input from the environment
    let input_bytes: Vec<u8> = sp1_zkvm::io::read_vec();

    // Deserialize the input
    let input = Input::try_from_slice(&input_bytes).unwrap();

    // Verify the input (performs ECDSA verification)
    let output = verify_input(input);

    // commit the output
    sp1_zkvm::io::commit_slice(output.as_slice());
}
