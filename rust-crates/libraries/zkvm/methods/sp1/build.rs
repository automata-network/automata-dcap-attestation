use std::{env, path::PathBuf, process::Command};

fn main() {
    assert!(
        env::var_os("SP1_SKIP_PROGRAM_BUILD").is_none(),
        "V2 release builds cannot skip guest compilation"
    );

    // The succinct distribution does not include Cargo. Falling back to a new
    // system Cargo can pass rustc flags unsupported by the pinned guest compiler.
    // Pin Cargo for child processes only; sp1-build still explicitly selects
    // rustc +succinct, its sysroot, target and codegen flags for the guest.
    let cargo_version = Command::new("rustup")
        .args(["run", "1.96.0", "cargo", "--version"])
        .output()
        .expect("rustup is required for the SP1 V2 build");
    assert!(
        cargo_version.status.success() && cargo_version.stdout.starts_with(b"cargo 1.96."),
        "SP1 6.8.0 builds require Cargo 1.96: rustup toolchain install 1.96.0 --profile minimal"
    );
    env::set_var("RUSTUP_TOOLCHAIN", "1.96.0");

    let targets = Command::new("rustc")
        .args(["+succinct", "--print", "target-list"])
        .output()
        .expect("SP1 v6 succinct toolchain is required");
    assert!(targets.status.success()
        && String::from_utf8_lossy(&targets.stdout).lines()
            .any(|target| target == sp1_build::DEFAULT_TARGET),
        "Install the SP1 6.8.0 toolchain with riscv64im-succinct-zkvm-elf support; v5 is incompatible");

    let output =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("../../artifacts/v2.0");
    for (name, mode) in [
        ("dcap-sp1-guest-v2", "strict"),
        ("dcap-sp1-guest-v2-minimal", "minimal"),
    ] {
        sp1_build::build_program_with_args(
            "./program",
            sp1_build::BuildArgs {
                binaries: vec![name.into()],
                output_directory: Some(output.to_string_lossy().into_owned()),
                elf_name: Some(format!("sp1-{mode}.elf")),
                locked: true,
                ..Default::default()
            },
        );
        let elf =
            std::fs::read(output.join(format!("sp1-{mode}.elf"))).expect("guest output missing");
        assert!(
            elf.len() >= 20 && &elf[..6] == b"\x7fELF\x02\x01" && elf[18..20] == [0xf3, 0],
            "SP1 v6 requires a little-endian ELF64 RISC-V program"
        );
    }
    println!("cargo:rerun-if-changed=program");
    println!("cargo:rerun-if-changed=../../../dcap-rs");
}
