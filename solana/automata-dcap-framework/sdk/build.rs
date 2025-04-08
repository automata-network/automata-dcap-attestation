use std::{fs, path::Path};


fn main() {
    println!("cargo:rerun-if-changed=target/idl");

    // Get the current directory (where Cargo.toml is located)
    let current_dir = std::env::current_dir().unwrap();

    // Create sdk/idl directory if it doesn't exist
    let sdk_idl_dir_path = current_dir.join("idls");
    fs::create_dir_all(&sdk_idl_dir_path).unwrap_or_else(|e| {
        eprintln!("Failed to create sdk/idl directory: {}", e);
    });

    let target_idl = Path::new("../target/idl");
    if target_idl.exists() {
        for entry in fs::read_dir(target_idl).unwrap().flatten() {
            if entry.path().is_file() && entry.path().extension().map_or(false, |ext| ext == "json") {
                let dest_path = sdk_idl_dir_path.join(entry.file_name());
                fs::copy(&entry.path(), &dest_path).unwrap();
            }
        }
    }
}
