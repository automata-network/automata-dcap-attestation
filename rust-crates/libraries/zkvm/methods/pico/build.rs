use automata_dcap_utils::Version;
use std::{env, fs, path::PathBuf, process::Command, str::FromStr};

fn main() {
    let force_build = env::var("FORCE_BUILD").is_ok();
    let version = get_target_version().expect("Invalid DCAP_VERSION");

    // Pico is only supported in v1.1+
    if version == Version::V1_0 {
        println!(
            "cargo::warning=Skipping Pico build: {} not supported (requires v1.1+)",
            version
        );
        return;
    }

    // Construct output path: ../../src/pico/guest/v1_1/elf/
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let version_dir = version.as_str().replace(".", "_"); // v1.1 -> v1_1
    let output_dir = manifest_dir
        .join("../../src/pico/guest")
        .join(&version_dir)
        .join("elf");
    let final_elf = output_dir.join("dcap-pico-guest-elf");

    // Skip if exists and FORCE_BUILD not set
    if !force_build && final_elf.exists() {
        println!("cargo::warning=Skipping Pico {} (ELF exists)", version);
        println!("cargo::rerun-if-changed={}", final_elf.display());
        return;
    }

    println!("cargo::warning=Building Pico guest for {}", version);

    // Build directly into the final output directory
    fs::create_dir_all(&output_dir).expect("Failed to create output directory");

    let program_dir = manifest_dir.join("program");

    let status = Command::new("cargo")
        .args(["pico", "build"])
        .arg("--output-directory")
        .arg(&output_dir)
        .current_dir(&program_dir)
        .status()
        .expect("Failed to execute 'cargo pico build'. Is cargo-pico installed?");

    if !status.success() {
        panic!(
            "cargo pico build failed with exit code: {:?}",
            status.code()
        );
    }

    // Rename: cargo-pico hardcodes the output filename, but the embedding
    // code expects "dcap-pico-guest-elf" (see src/pico/guest/v1_1/elf/mod.rs)
    let built_elf = output_dir.join("riscv32im-pico-zkvm-elf");
    if !built_elf.exists() {
        panic!("Expected built ELF not found at {}", built_elf.display());
    }

    fs::rename(&built_elf, &final_elf).unwrap_or_else(|e| {
        panic!(
            "Failed to rename {} -> {}: {}",
            built_elf.display(),
            final_elf.display(),
            e
        )
    });

    println!(
        "cargo::warning=Built Pico guest ELF at {}",
        final_elf.display()
    );

    // Dependency tracking
    println!("cargo::rerun-if-changed=./program/src/main.rs");
    println!("cargo::rerun-if-changed=./program/Cargo.toml");
}

fn get_target_version() -> Result<Version, anyhow::Error> {
    match env::var("DCAP_VERSION") {
        Ok(v) => Version::from_str(&v).map_err(|e| anyhow::anyhow!("{}", e)),
        Err(_) => Ok(Version::V1_1),
    }
}
