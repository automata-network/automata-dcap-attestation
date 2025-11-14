use anyhow::Result;
use std::{fs, path::Path};

const OUT_DIR_STR: &str = "./out/";

pub fn print_content(filename: &str, content: &[u8]) -> Result<()> {
    check_out_exists()?;

    let path = format!("{}{}", OUT_DIR_STR, filename);
    fs::write(path, content)?;

    Ok(())
}

pub fn print_str_content(filename: &str, str_content: &str) -> Result<()> {
    check_out_exists()?;

    let path = format!("{}{}", OUT_DIR_STR, filename);
    fs::write(path, str_content)?;

    Ok(())
}

fn check_out_exists() -> Result<()> {
    let out_dir_path = Path::new(OUT_DIR_STR);
    if !out_dir_path.exists() {
        fs::create_dir(out_dir_path)?;
    }

    Ok(())
}
