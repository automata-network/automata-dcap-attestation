use anyhow::Result;

/// Metadata extracted from a DCAP quote header
#[derive(Debug, Clone)]
pub struct QuoteMetadata {
    /// Quote version (bytes 0-1, little-endian)
    pub version: u16,
    /// TEE type (bytes 4-7, little-endian)
    pub tee_type: u32,
}

impl QuoteMetadata {
    /// Parse quote metadata from raw quote bytes
    ///
    /// # Arguments
    /// * `quote` - Raw quote bytes
    ///
    /// # Returns
    /// Parsed quote metadata
    pub fn from_quote(quote: &[u8]) -> Result<Self> {
        if quote.len() < 8 {
            anyhow::bail!("Quote too short to parse metadata (need at least 8 bytes)");
        }

        let version = u16::from_le_bytes([quote[0], quote[1]]);
        let tee_type = u32::from_le_bytes([quote[4], quote[5], quote[6], quote[7]]);

        Ok(Self { version, tee_type })
    }

    /// Log quote metadata using the log crate
    pub fn log_info(&self) {
        log::info!("Quote version: {}", self.version);
        log::info!("TEE Type: {}", self.tee_type);
    }
}
