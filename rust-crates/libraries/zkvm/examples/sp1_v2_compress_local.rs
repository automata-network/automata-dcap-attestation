//! Guard the removed v5-only checkpoint protocol against accidental reuse.
fn main() -> anyhow::Result<()> {
    anyhow::bail!("The v5 core/outer checkpoint protocol is incompatible with SP1 6.8.0. Use sp1_v2_prove_local PROGRAM INPUT PROOF --kind groth16 [--minimal] with the new ELF64 guest. No old checkpoint was read or converted.")
}
