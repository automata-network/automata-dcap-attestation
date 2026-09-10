use std::{env, fs, path::PathBuf, process::Command};
fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let output = manifest.join("../../artifacts/v2.0");
    fs::create_dir_all(&output).unwrap();
    let status = Command::new("cargo")
        .args(["pico", "build", "--output-directory"])
        .arg(&output)
        .current_dir(manifest.join("program"))
        .status()
        .expect("cargo-pico v1.1.6 is required");
    assert!(status.success(), "Pico V2 guest build failed");
    fs::rename(
        output.join("riscv32im-pico-zkvm-elf"),
        output.join("pico.elf"),
    )
    .unwrap();
    println!("cargo:rerun-if-changed=program");
    println!("cargo:rerun-if-changed=../../../dcap-rs");
}
