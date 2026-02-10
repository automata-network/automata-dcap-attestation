use sp1_build::{build_program_with_args, BuildArgs};
use automata_dcap_utils::Version;
use std::{env, path::PathBuf, str::FromStr};

fn main() {
    // Parse environment
    let use_docker = env::var("USE_DOCKER").is_ok();
    let force_build = env::var("FORCE_BUILD").is_ok();
    let version = get_target_version().expect("Invalid DCAP_VERSION");

    // Construct output path: ../../src/sp1/guest/v1_1/elf/
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let version_dir = version.as_str().replace(".", "_"); // v1.0 -> v1_0
    let output_dir = manifest_dir
        .join("../../src/sp1/guest")
        .join(format!("{}", version_dir))
        .join("elf");
    let elf_path = output_dir.join("dcap-sp1-guest-program-elf");

    // Skip if exists and FORCE_BUILD not set
    if !force_build && elf_path.exists() {
        println!("cargo::warning=Skipping SP1 {} (ELF exists)", version);
        println!("cargo::rerun-if-changed={}", elf_path.display());
        return;
    }

    println!("cargo::warning=Building SP1 guest for {}", version);

    // Workspace root for Docker
    let workspace_directory = if use_docker {
        let root = manifest_dir.ancestors().nth(4)
            .expect("Cannot find workspace root");
        Some(root.to_string_lossy().to_string())
    } else {
        None
    };

    // Build using sp1-build
    build_program_with_args(
        "./program",
        BuildArgs {
            output_directory: Some(output_dir.to_string_lossy().to_string()),
            elf_name: Some("dcap-sp1-guest-program-elf".to_string()),
            docker: use_docker,
            workspace_directory,
            ..Default::default()
        },
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
