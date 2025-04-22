use std::sync::Arc;

use anchor_client::solana_sdk::signature::{read_keypair_file, Keypair};

#[cfg(test)]
mod test_pck_certificate;

#[cfg(test)]
mod test_pcs_certificate;

#[cfg(test)]
mod test_enclave_identity;

#[cfg(test)]
mod test_tcb_info;


pub fn get_signer() -> Arc<Keypair> {
    let anchor_wallet =
        std::env::var("ANCHOR_WALLET").expect("ANCHOR_WALLET environment variable not set");
    let payer = read_keypair_file(&anchor_wallet).expect("Failed to read keypair file");
    Arc::new(payer)
}
