use std::{
    env, fs,
    path::Path,
    process::{Command, Stdio},
};

const CONTRACTS: &[&str] = &[
    "IEnclaveIdentityDao",
    "IFmspcTcbDao",
    "IPcsDao",
    "IPckDao",
    "ITcbEvalDao",
    "IAutomataDcapAttestation",
    "IPCCSRouter",
];

fn main() {
    println!("cargo:rerun-if-env-changed=AUTOMATA_UPDATE_BINDINGS");
    println!("cargo:rerun-if-changed=../../evm/foundry.toml");
    println!("cargo:rerun-if-changed=../../evm/contracts");

    // Only regenerate bindings when explicitly requested. This prevents every
    // `cargo build` from depending on `forge`, but keeps the workflow available
    // when the ABI changes.
    let should_update = matches!(
        env::var("AUTOMATA_UPDATE_BINDINGS"),
        Ok(val) if val == "1" || val.eq_ignore_ascii_case("true")
    );

    if !should_update {
        return;
    }

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let evm_root = manifest_dir.join("../../evm");
    let bindings_path = manifest_dir.join("src/bindings");

    if bindings_path.exists() {
        fs::remove_dir_all(&bindings_path).expect("failed to clear existing bindings directory");
    }
    fs::create_dir_all(&bindings_path).expect("failed to create bindings directory");

    run(Command::new("forge")
        .args(["build", "--quiet"])
        .current_dir(&evm_root));

    run(Command::new("forge")
        .arg("bind")
        .arg("--module")
        .arg("--overwrite")
        .arg("--bindings-path")
        .arg(bindings_path.to_str().expect("non-utf8 path"))
        .args(
            CONTRACTS
                .iter()
                .flat_map(|contract| ["--select", *contract])
                .collect::<Vec<_>>(),
        )
        .current_dir(&evm_root));
}

fn run(cmd: &mut Command) {
    let status = cmd
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .expect("failed to spawn command");

    if !status.success() {
        panic!("command {:?} exited with {:?}", cmd, status);
    }
}
