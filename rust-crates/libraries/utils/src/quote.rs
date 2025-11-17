use anyhow::{Context, Result};
use std::fs;

/// Reads a quote from a file path. The file can contain either:
/// - Binary quote data (returned as-is)
/// - Hex-encoded quote string (decoded and returned)
///
/// The function automatically detects whether the file contains hex or binary data.
pub fn read_from_path(path: &str) -> Result<Vec<u8>> {
    let bytes = fs::read(path).with_context(|| format!("failed to read quote file {}", path))?;

    if looks_like_hex(&bytes) {
        let as_str = String::from_utf8_lossy(&bytes);
        parse_hex(as_str.trim()).with_context(|| format!("invalid hex in {}", path))
    } else {
        Ok(bytes) // Return binary data as-is
    }
}

/// Parses a hex string and returns the decoded bytes.
/// Supports hex strings with or without "0x" prefix.
/// Automatically strips whitespace and newlines.
pub fn parse_hex(hex_str: &str) -> Result<Vec<u8>> {
    let normalized = hex_str.trim().trim_start_matches("0x");
    let normalized = normalized.replace(['\n', '\r', ' ', '\t'], "");

    let decoded = hex::decode(&normalized).with_context(|| {
        format!(
            "failed to decode quote hex (length {})",
            normalized.len()
        )
    })?;

    Ok(decoded)
}

/// Checks if the given bytes look like a hex string.
/// Returns true if all non-whitespace bytes are hex digits or 'x'/'X' characters.
fn looks_like_hex(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .filter(|b| !b.is_ascii_whitespace())
        .all(|b| b.is_ascii_hexdigit() || *b == b'x' || *b == b'X')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex_with_0x_prefix() {
        let result = parse_hex("0x48656c6c6f").unwrap();
        assert_eq!(result, b"Hello");
    }

    #[test]
    fn test_parse_hex_without_prefix() {
        let result = parse_hex("48656c6c6f").unwrap();
        assert_eq!(result, b"Hello");
    }

    #[test]
    fn test_parse_hex_with_whitespace() {
        let result = parse_hex("48 65 6c 6c 6f").unwrap();
        assert_eq!(result, b"Hello");
    }

    #[test]
    fn test_parse_hex_with_newlines() {
        let result = parse_hex("4865\n6c6c\n6f").unwrap();
        assert_eq!(result, b"Hello");
    }

    #[test]
    fn test_looks_like_hex() {
        assert!(looks_like_hex(b"0x48656c6c6f"));
        assert!(looks_like_hex(b"48656c6c6f"));
        assert!(looks_like_hex(b"48 65 6c 6c 6f"));
        assert!(!looks_like_hex(b"\x00\x01\x02\x03"));
        assert!(!looks_like_hex(b"Hello World"));
    }
}
