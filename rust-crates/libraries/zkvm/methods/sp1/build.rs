use std::{env, path::PathBuf};
fn main() {
    assert!(
        env::var_os("SP1_SKIP_PROGRAM_BUILD").is_none(),
        "V2 release builds cannot skip guest compilation"
    );
    let output =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("../../artifacts/v2.0");
    sp1_build::build_program_with_args(
        "./program",
        sp1_build::BuildArgs {
            output_directory: Some(output.to_string_lossy().into_owned()),
            elf_name: Some("sp1.elf".into()),
            locked: true,
            ..Default::default()
        },
    );
    println!("cargo:rerun-if-changed=program");
    println!("cargo:rerun-if-changed=../../../dcap-rs");
}
