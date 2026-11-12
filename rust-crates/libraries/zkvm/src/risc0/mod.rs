pub mod cli;
pub mod config;
pub mod guest;
pub mod prover;
pub mod proving;

pub use cli::{run, Risc0Command, Risc0ProveArgs};
pub use config::{BonsaiConfig, BoundlessConfig, BoundlessProofType, ProvingStrategy, Risc0Config};
pub use prover::Risc0Prover;
pub use proving::{prove_with_bonsai, prove_with_boundless};

use risc0_zkvm::{
    sha::{Digest, Digestible},
    Groth16Receipt, Groth16ReceiptVerifierParameters, ReceiptClaim, VerifierContext,
};

/// Export the pinned SDK's Groth16 format; on-chain routes are configured independently.
pub fn validate_v2_seal(seal: &[u8]) -> anyhow::Result<()> {
    let parameters = Groth16ReceiptVerifierParameters::default().digest();
    anyhow::ensure!(
        seal.len() == 260 && seal[..4] == parameters.as_bytes()[..4],
        "V2 requires the pinned RISC Zero SDK's Groth16 seal"
    );
    Ok(())
}

/// Bind remote proof bytes to the locally executed program and journal, without dev mode.
pub fn verify_v2_seal(seal: &[u8], image_id: Digest, journal: &[u8]) -> anyhow::Result<()> {
    validate_v2_seal(seal)?;
    let parameters = Groth16ReceiptVerifierParameters::default();
    let receipt = Groth16Receipt::<ReceiptClaim>::new(
        seal[4..].to_vec(),
        ReceiptClaim::ok(image_id, journal.to_vec()).into(),
        parameters.digest(),
    );
    receipt.verify_integrity_with_context(
        &VerifierContext::empty().with_groth16_verifier_parameters(parameters),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    fn fixture(source: &str) -> (Vec<u8>, super::Digest, Vec<u8>) {
        let field = |name: &str| {
            let value = source
                .split(&format!("constant {name} ="))
                .nth(1)
                .unwrap()
                .trim();
            if let Some(value) = value.strip_prefix("hex\"") {
                hex::decode(value.split('"').next().unwrap()).unwrap()
            } else {
                hex::decode(value.strip_prefix("0x").unwrap().split(';').next().unwrap()).unwrap()
            }
        };
        (
            field("SEAL"),
            super::Digest::try_from(field("IMAGE_ID").as_slice()).unwrap(),
            field("JOURNAL"),
        )
    }

    #[test]
    fn v2_seal_authenticates_image_journal_and_proof() {
        let (seal, image, journal) = fixture(include_str!(
            "../../../../../evm/lib/risc0-ethereum/contracts/test/TestReceiptV3_1.sol"
        ));
        super::verify_v2_seal(&seal, image, &journal).unwrap();
        assert!(super::verify_v2_seal(&seal, super::Digest::ZERO, &journal).is_err());
        assert!(super::verify_v2_seal(&seal, image, b"changed journal").is_err());
        let mut changed = seal.clone();
        changed[259] ^= 1;
        assert!(super::verify_v2_seal(&changed, image, &journal).is_err());
        changed[4..].fill(0);
        assert!(super::verify_v2_seal(&changed, image, &journal).is_err());
    }

    #[test]
    fn old_proof_cannot_be_repaired_by_relabeling_its_selector() {
        let (mut seal, image, journal) = fixture(include_str!(
            "../../../../../evm/lib/risc0-ethereum/contracts/test/TestReceiptV3_0.sol"
        ));
        assert!(super::verify_v2_seal(&seal, image, &journal).is_err());
        use super::Digestible;
        seal[..4].copy_from_slice(
            &super::Groth16ReceiptVerifierParameters::default()
                .digest()
                .as_bytes()[..4],
        );
        assert!(super::verify_v2_seal(&seal, image, &journal).is_err());
    }

    #[test]
    fn sdk_parameters_match_the_v2_contract_selector() {
        use risc0_zkvm::{sha::Digestible, Groth16ReceiptVerifierParameters};
        assert_eq!(
            &Groth16ReceiptVerifierParameters::default()
                .digest()
                .as_bytes()[..4],
            &[0xe7, 0x1e, 0x66, 0x20],
        );
    }

    #[test]
    fn v2_seal_requires_current_selector_and_exact_length() {
        for selector in [
            [0x73, 0xc4, 0x57, 0xba],
            [0x24, 0x2f, 0x9d, 0x5b],
            [0xff; 4],
            [0; 4],
        ] {
            let mut seal = vec![0; 260];
            seal[..4].copy_from_slice(&selector);
            assert!(super::validate_v2_seal(&seal).is_err());
        }
        let mut seal = vec![0; 260];
        seal[..4].copy_from_slice(&[0xe7, 0x1e, 0x66, 0x20]);
        assert!(super::validate_v2_seal(&seal).is_ok());
        for length in [0, 3, 4, 259] {
            assert!(super::validate_v2_seal(&seal[..length]).is_err());
        }
        seal.push(0);
        assert!(super::validate_v2_seal(&seal).is_err());
    }
}
