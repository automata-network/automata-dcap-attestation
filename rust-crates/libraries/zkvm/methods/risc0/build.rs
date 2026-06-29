use risc0_build::{embed_methods_with_options, DockerOptionsBuilder, GuestOptionsBuilder};
use automata_dcap_utils::Version;
use std::{collections::HashMap, env, fs, path::PathBuf, str::FromStr};

fn main() {
    // Parse environment
    let use_docker = env::var("USE_DOCKER").is_ok();
    let force_build = env::var("FORCE_BUILD").is_ok();
    let version = get_target_version().expect("Invalid DCAP_VERSION");

    // Construct output path: ../../src/risc0/guest/v1_1/elf/guest
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let version_dir = version.as_str().replace(".", "_"); // v1.1 -> v1_1
    let output_dir = manifest_dir
        .join("../../src/risc0/guest")
        .join(&version_dir)
        .join("elf");
    let final_elf = output_dir.join("guest");

    // Skip if exists and FORCE_BUILD not set
    if !force_build && final_elf.exists() {
        println!("cargo::warning=Skipping RISC0 {} (ELF exists)", version);
        println!("cargo::rerun-if-changed={}", final_elf.display());
        return;
    }

    println!("cargo::warning=Building RISC0 guest for {}", version);

    // Configure Docker if requested
    let mut builder = GuestOptionsBuilder::default();
    if use_docker {
        let root = manifest_dir.ancestors().nth(4)
            .expect("Cannot find workspace root");
        let docker_opts = DockerOptionsBuilder::default()
            .root_dir(root)
            .build()
            .unwrap();
        builder.use_docker(docker_opts);
    }

    // Build using risc0-build
    // HashMap uses package name as key
    embed_methods_with_options(
        HashMap::from([("dcap-risc0-guest", builder.build().unwrap())])
    );

    // Copy from target to output directory
    fs::create_dir_all(&output_dir).expect("Failed to create output dir");

    let profile = if use_docker { "docker" } else { "release" };
    let workspace_root = manifest_dir.ancestors().nth(4).unwrap();
    // risc0-build creates: target/riscv-guest/{wrapper-crate}/{guest-package}/riscv32im-risc0-zkvm-elf/{profile}/guest.bin
    let src_elf = workspace_root.join(format!(
        "target/riscv-guest/dcap-risc0-methods/dcap-risc0-guest/riscv32im-risc0-zkvm-elf/{}/guest.bin",
        profile
    ));

    fs::copy(&src_elf, &final_elf)
        .unwrap_or_else(|e| panic!(
            "Failed to copy {} -> {}: {}",
            src_elf.display(), final_elf.display(), e
        ));

    println!("cargo::warning=Built RISC0 guest ELF at {}", final_elf.display());

    // Dependency tracking
    println!("cargo::rerun-if-changed=./guest/src/main.rs");
    println!("cargo::rerun-if-changed=./guest/Cargo.toml");
}

fn get_target_version() -> Result<Version, anyhow::Error> {
    match env::var("DCAP_VERSION") {
        Ok(v) => Version::from_str(&v).map_err(|e| anyhow::anyhow!("{}", e)),
        Err(_) => Ok(Version::V1_1),
    }
}
