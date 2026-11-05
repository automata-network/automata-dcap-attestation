use std::{env, path::Path, process::Command};

// Only the compiler is updated. Keep Pico v1.1.6's target and codegen contract.
pub const TOOLCHAIN: &str = "nightly-2025-08-04";
pub const TARGET: &str = "riscv32im-risc0-zkvm-elf";
const RUSTFLAGS: &[&str] = &[
    "-C",
    "passes=lower-atomic",
    "-C",
    "link-arg=-Ttext=0x00200800",
    "-C",
    "link-arg=--fatal-warnings",
    "-C",
    "panic=abort",
];

pub fn guest_command(program: &Path, target: &Path) -> Command {
    let mut command = Command::new("rustup");
    command
        .args(["run", TOOLCHAIN, "cargo", "build", "--release", "--locked"])
        .args(["--target", TARGET])
        .args(["-Z", "build-std=alloc,core,proc_macro,panic_abort,std"])
        .args(["-Z", "build-std-features=compiler-builtins-mem"])
        .arg("--manifest-path")
        .arg(program.join("Cargo.toml"))
        .arg("--target-dir")
        .arg(target)
        .current_dir(program);

    // The outer build script receives its host compiler and flags through env.
    // Let rustup select the pinned guest compiler instead, without dropping the
    // caller's registry, proxy, offline or Cargo cache settings.
    for key in [
        "RUSTUP_TOOLCHAIN",
        "RUSTC",
        "RUSTDOC",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "RUSTFLAGS",
        "RUSTDOCFLAGS",
        "CARGO_ENCODED_RUSTDOCFLAGS",
    ] {
        command.env_remove(key);
    }
    for (key, _) in env::vars_os() {
        if key
            .to_str()
            .is_some_and(|key| key.starts_with("CARGO_FEATURE_") || key.starts_with("CARGO_CFG_"))
        {
            command.env_remove(key);
        }
    }
    command.env("CARGO_ENCODED_RUSTFLAGS", RUSTFLAGS.join("\x1f"));
    command
}

pub fn validate_elf(elf: &[u8]) -> Result<(), &'static str> {
    if elf.len() < 52 || &elf[..4] != b"\x7fELF" {
        return Err("missing ELF32 header");
    }
    if elf[4..7] != [1, 1, 1] {
        return Err("guest must be ELF32, little-endian, ELF version 1");
    }
    if u16::from_le_bytes([elf[16], elf[17]]) != 2 {
        return Err("guest must be an executable");
    }
    if u16::from_le_bytes([elf[18], elf[19]]) != 243 {
        return Err("guest must target RISC-V");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn inner_build_is_locked_and_pins_the_toolchain_and_target() {
        let command = guest_command(Path::new("/guest"), Path::new("/isolated-target"));
        assert_eq!(command.get_program(), "rustup");
        let args: Vec<_> = command
            .get_args()
            .map(|arg| arg.to_str().unwrap())
            .collect();
        assert_eq!(
            &args[..6],
            ["run", TOOLCHAIN, "cargo", "build", "--release", "--locked"]
        );
        assert!(args.windows(2).any(|args| args == ["--target", TARGET]));
        assert!(args
            .windows(2)
            .any(|args| args == ["--target-dir", "/isolated-target"]));
        assert!(args.contains(&"build-std=alloc,core,proc_macro,panic_abort,std"));
        assert!(args.contains(&"build-std-features=compiler-builtins-mem"));
    }

    #[test]
    fn retains_pico_codegen_flags_and_clears_host_compiler_overrides() {
        let command = guest_command(Path::new("/guest"), Path::new("/isolated-target"));
        let vars: Vec<_> = command.get_envs().collect();
        for name in [
            "RUSTC",
            "RUSTUP_TOOLCHAIN",
            "RUSTFLAGS",
            "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER",
        ] {
            assert!(vars.contains(&(OsStr::new(name), None)));
        }
        assert!(vars.contains(&(
            OsStr::new("CARGO_ENCODED_RUSTFLAGS"),
            Some(OsStr::new("-C\x1fpasses=lower-atomic\x1f-C\x1flink-arg=-Ttext=0x00200800\x1f-C\x1flink-arg=--fatal-warnings\x1f-C\x1fpanic=abort")),
        )));
    }

    #[test]
    fn validates_riscv32_executable_header() {
        let mut elf = [0; 52];
        elf[..7].copy_from_slice(b"\x7fELF\x01\x01\x01");
        elf[16] = 2;
        elf[18] = 243;
        assert!(validate_elf(&elf).is_ok());
        for offset in [0, 4, 5, 6, 16, 18] {
            let mut invalid = elf;
            invalid[offset] = 0;
            assert!(validate_elf(&invalid).is_err(), "offset {offset}");
        }
        for length in 0..52 {
            assert!(validate_elf(&elf[..length]).is_err());
        }
    }
}
