use std::{env, fs, path::PathBuf};
fn main() {
    assert!(
        env::var_os("RISC0_SKIP_BUILD").is_none(),
        "V2 release builds cannot skip guest compilation"
    );
    let entries = risc0_build::embed_methods();
    let guest = entries.first().expect("missing V2 guest build");
    assert!(!guest.elf.is_empty(), "empty V2 guest ELF");
    let output =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("../../artifacts/v2.0");
    fs::create_dir_all(&output).unwrap();
    fs::write(output.join("risc0.elf"), &guest.elf).unwrap();
    fs::write(output.join("risc0.image-id"), guest.image_id.to_string()).unwrap();
    println!("cargo:rerun-if-changed=guest");
    println!("cargo:rerun-if-changed=../../../dcap-rs");
}
