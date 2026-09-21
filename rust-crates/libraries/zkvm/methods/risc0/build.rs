use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    assert!(
        env::var_os("RISC0_SKIP_BUILD").is_none(),
        "V2 release builds cannot skip guest compilation"
    );

    // risc0-build selects the rzup compiler but invokes plain Cargo, stripping
    // RUSTUP_TOOLCHAIN from its environment. Put the pinned Cargo binary first
    // on the child PATH; newer Cargo can emit rustc flags Rust 1.88 rejects.
    let cargo = Command::new("rustup")
        .args(["which", "--toolchain", "1.88.0", "cargo"])
        .output()
        .expect("rustup is required for the RISC Zero V2 build");
    assert!(
        cargo.status.success(),
        "RISC Zero V2 requires Cargo 1.88: rustup toolchain install 1.88.0 --profile minimal"
    );
    let cargo_path = PathBuf::from(String::from_utf8(cargo.stdout).unwrap().trim());
    let mut paths = vec![cargo_path.parent().unwrap().to_path_buf()];
    paths.extend(env::split_paths(&env::var_os("PATH").unwrap_or_default()));
    env::set_var("PATH", env::join_paths(paths).unwrap());
    // Outer cargo --locked does not automatically apply to the guest build.
    env::set_var("RISC0_BUILD_LOCKED", "1");

    let entries = risc0_build::embed_methods();
    let output =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("../../artifacts/v2.0");
    fs::create_dir_all(&output).unwrap();
    for (name, mode) in [("guest", "strict"), ("guest-minimal", "minimal")] {
        let guest = entries
            .iter()
            .find(|entry| entry.name == name)
            .expect("missing V2 guest mode");
        assert!(!guest.elf.is_empty(), "empty V2 guest ELF");
        fs::write(output.join(format!("risc0-{mode}.elf")), &guest.elf).unwrap();
        fs::write(
            output.join(format!("risc0-{mode}.image-id")),
            guest.image_id.to_string(),
        )
        .unwrap();
    }
    println!("cargo:rerun-if-changed=guest");
    println!("cargo:rerun-if-changed=../../../dcap-rs");
}
