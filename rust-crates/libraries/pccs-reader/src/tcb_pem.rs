use anyhow::Result;
use pem::{encode, Pem};

/// Generates a PEM-encoded certificate chain from TCB signing and root CA certificates.
///
/// This function takes DER-encoded certificates and converts them to a PEM chain
/// suitable for use in TLS verification or other certificate validation contexts.
///
/// # Arguments
///
/// * `tcb_signing_ca_der` - DER-encoded TCB signing CA certificate
/// * `root_ca_der` - DER-encoded root CA certificate
///
/// # Returns
///
/// A PEM-encoded string containing both certificates in chain order (signing CA first,
/// then root CA).
///
/// # Examples
///
/// ```no_run
/// # use automata_dcap_pccs_reader::tcb_pem::generate_tcb_issuer_chain_pem;
/// # fn example() -> anyhow::Result<()> {
/// let tcb_signing_der = vec![/* ... */];
/// let root_ca_der = vec![/* ... */];
/// let pem_chain = generate_tcb_issuer_chain_pem(&tcb_signing_der, &root_ca_der)?;
/// println!("{}", pem_chain);
/// # Ok(())
/// # }
/// ```
pub fn generate_tcb_issuer_chain_pem(
    tcb_signing_ca_der: &[u8],
    root_ca_der: &[u8],
) -> Result<String> {
    let mut pem_chain = String::new();

    let tcb_pem = Pem::new(
        String::from("CERTIFICATE"),
        tcb_signing_ca_der.to_vec(),
    );

    let root_pem = Pem::new(
        String::from("CERTIFICATE"),
        root_ca_der.to_vec(),
    );

    pem_chain.push_str(&encode(&tcb_pem));
    pem_chain.push_str(&encode(&root_pem));

    Ok(pem_chain)
}
