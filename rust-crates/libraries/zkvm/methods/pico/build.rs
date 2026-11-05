mod build_support;

use std::{env, fs, path::PathBuf};

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    // Never share the outer Cargo target directory: nested Cargo would deadlock.
    let target = PathBuf::from(env::var("OUT_DIR").unwrap()).join("guest-target");
    let status = build_support::guest_command(&manifest.join("program"), &target)
        .status()
        .expect("rustup and nightly-2025-08-04 with rust-src are required");
    assert!(
        status.success(),
        "Pico V2 guest build failed; no ELF published"
    );

    let output = manifest.join("../../artifacts/v2.0");
    fs::create_dir_all(&output).unwrap();
    for (name, mode) in [
        ("dcap-pico-guest-v2", "strict"),
        ("dcap-pico-guest-v2-minimal", "minimal"),
    ] {
        let elf = fs::read(
            target
                .join(build_support::TARGET)
                .join("release")
                .join(name),
        )
        .expect("Pico V2 guest mode missing after build");
        build_support::validate_elf(&elf).expect("invalid Pico V2 guest executable");
        // Mode-specific filenames prevent the default from depending on build order.
        let pending = output.join(format!("pico-{mode}.elf.{}.tmp", std::process::id()));
        fs::write(&pending, elf).unwrap();
        fs::rename(pending, output.join(format!("pico-{mode}.elf"))).unwrap();
    }
    println!("cargo:rerun-if-changed=program");
    println!("cargo:rerun-if-changed=../../../dcap-rs");
    println!("cargo:rerun-if-changed=build_support.rs");
}
