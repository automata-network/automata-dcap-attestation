use std::{env, path::PathBuf, process::Command};

fn main() {
    assert!(
        env::var_os("SP1_SKIP_PROGRAM_BUILD").is_none(),
        "V2 release builds cannot skip guest compilation"
    );

    // The succinct distribution does not include Cargo. Falling back to a new
    // system Cargo can pass rustc flags unsupported by succinct's Rust 1.88.
    // Pin Cargo for child processes only; sp1-build still explicitly selects
    // rustc +succinct, its sysroot, target and codegen flags for the guest.
    let cargo_version = Command::new("rustup")
        .args(["run", "1.88.0", "cargo", "--version"])
        .output()
        .expect("rustup is required for the SP1 V2 build");
    assert!(
        cargo_version.status.success() && cargo_version.stdout.starts_with(b"cargo 1.88."),
        "SP1 V2 requires Cargo 1.88: rustup toolchain install 1.88.0 --profile minimal"
    );
    env::set_var("RUSTUP_TOOLCHAIN", "1.88.0");

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
