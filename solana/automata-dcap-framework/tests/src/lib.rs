mod pccs;
mod verifier;
use anchor_client::solana_sdk::{pubkey::Pubkey, signer::keypair::Keypair, signature::read_keypair_file};
use std::sync::Arc;

pub const TEST_RISC0_VERIFIER_PUBKEY: Pubkey =
    Pubkey::from_str_const("5Gxa8YTih2rg3NY5EuWLtpS3Eq5xpS7PKWxspAAni5RS");

pub const ROOT_CRL_BYTES: &[u8] = include_bytes!("../data/intel_root_ca_crl.der");

pub fn get_signer() -> Arc<Keypair> {
    let anchor_wallet =
        std::env::var("ANCHOR_WALLET").expect("ANCHOR_WALLET environment variable not set");
    let payer = read_keypair_file(&anchor_wallet).expect("Failed to read keypair file");
    Arc::new(payer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sdk::Sdk;
    use solana_zk_tests::zkvm::risc0::deploy_risc0_groth16_verifier;
    use anchor_client::solana_client::nonblocking::rpc_client::RpcClient;
    use anchor_client::solana_sdk::commitment_config::CommitmentConfig;

    /// NOTE: Currently I can't specify a timestamp for the local validator to start at.
    /// Tests may fail due to expired collaterals

    #[tokio::test]
    pub async fn test_suite() {
        println!("=== SETTING UP TEST ENVIRONMENT ===");
        let signer = get_signer();
        let sdk = Sdk::new(signer.clone(), None);

        let rpc_client = RpcClient::new_with_commitment(
            String::from("http://localhost:8899"),
            CommitmentConfig::confirmed(),
        );
        if rpc_client
            .get_account(&TEST_RISC0_VERIFIER_PUBKEY)
            .await
            .is_err()
        {
            deploy_risc0_groth16_verifier(signer.as_ref(), &rpc_client)
                .await
                .unwrap();
        }
        println!("=== SETTING UP TEST ENVIRONMENT... DONE ===");

        println!("=== BEGIN UPSERTING INTEL ROOT CA ===");
        pccs::test_pcs_certificate::test_pcs_root_ca_upsert(&sdk).await;
        println!("=== BEGIN UPSERTING INTEL ROOT CA... DONE ===");

        println!("=== BEGIN UPSERTING INTEL ROOT CA CRL ===");
        pccs::test_pcs_certificate::test_pcs_root_crl_certificate_upsert(&sdk).await;
        println!("=== BEGIN UPSERTING INTEL ROOT CA CRL... DONE ===");

        println!("=== BEGIN UPSERTING INTEL TCB SIGNING CA ===");
        pccs::test_pcs_certificate::test_pcs_signing_certificate_upsert(&sdk).await;
        println!("=== BEGIN UPSERTING INTEL TCB SIGNING CA... DONE ===");

        println!("=== BEGIN UPSERTING INTEL PCK PLATFORM CA ===");
        pccs::test_pcs_certificate::test_pcs_platform_certificate_upsert(&sdk).await;
        println!("=== BEGIN UPSERTING INTEL PCK PLATFORM CA... DONE ===");

        println!("=== BEGIN UPSERTING INTEL PCK PLATFORM CA CRL ===");
        pccs::test_pcs_certificate::test_pcs_platform_crl_certificate_upsert(&sdk).await;
        println!("=== BEGIN UPSERTING INTEL PCK PLATFORM CA CRL... DONE ===");

        // println!("=== BEGIN UPSERTING QE IDENTITY ===");
        // pccs::test_enclave_identity::test_enclave_identity_upsert(&sdk).await;
        // println!("=== BEGIN UPSERTING QE IDENTITY... DONE ===");

        // println!("=== BEGIN UPSERTING FMSPC TCB INFO ===");
        // pccs::test_tcb_info::test_tcb_info_upsert_v3_tdx(&sdk).await;
        // println!("=== BEGIN UPSERTING FMSPC TCB INFO... DONE ===");

        // println!("=== BEGIN VERIFYING TDX QUOTE ===");
        // verifier::test_quote_verification::test_quote_tdx_verification(&sdk).await;
        // println!("=== BEGIN VERIFYING TDX QUOTE... DONE ===");
    }
}
