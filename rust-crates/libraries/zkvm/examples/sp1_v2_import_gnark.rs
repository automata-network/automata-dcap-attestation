//! Guard the removed v5 gnark transport and hard-coded verifier key.
fn main() -> anyhow::Result<()> {
    anyhow::bail!("The v5 gnark transport/key is incompatible with SP1 6.8.0. Generate and verify a new proof using sp1_v2_prove_local --kind groth16; its .evm.json contains SDK-encoded journal/proof/selector. No raw container result was trusted.")
}
