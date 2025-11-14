use sp1_build::{build_program_with_args, BuildArgs};
use sp1_sdk::SP1_CIRCUIT_VERSION;

fn main() {
    let use_docker = std::env::var("USE_DOCKER").is_ok();
    build_program_with_args(
        "../program",
        BuildArgs {
            output_directory: Some("../elf".to_string()),
            elf_name: Some("dcap-p256-sp1-program-elf".to_string()),
            docker: use_docker,
            tag: SP1_CIRCUIT_VERSION.to_string(),
            ..Default::default()
        },
    )
}