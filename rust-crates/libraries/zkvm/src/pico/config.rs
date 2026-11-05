use std::path::PathBuf;

/// Configuration for Pico zkVM proving
#[derive(Debug, Clone)]
pub struct PicoConfig {
    /// Path to the directory containing EVM proof artifacts (vm_pk, vm_vk, constraints.json)
    pub artifacts_path: PathBuf,

    /// This DCAP integration and its program identifiers use KoalaBear ("kb") only.
    pub field_type: String,
}

impl Default for PicoConfig {
    fn default() -> Self {
        Self {
            // Default to bundled artifacts in the crate
            artifacts_path: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/pico/artifacts"),
            field_type: "kb".to_string(),
        }
    }
}

impl PicoConfig {
    /// Reject unsupported fields before emulation, proving, or artifact generation.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.field_type == "kb",
            "DCAP Pico supports only the KoalaBear field (kb); got {}",
            self.field_type
        );
        Ok(())
    }

    /// Create a new PicoConfig with custom artifacts path
    pub fn new(artifacts_path: PathBuf) -> Self {
        Self {
            artifacts_path,
            field_type: "kb".to_string(),
        }
    }

    /// Set the field type for the proving backend
    pub fn with_field_type(mut self, field_type: String) -> Self {
        self.field_type = field_type;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_koala_bear_configuration_is_supported() {
        assert!(PicoConfig::default().validate().is_ok());
        for field in ["bb", "m31", "", "KB", "unknown"] {
            assert!(PicoConfig::default()
                .with_field_type(field.into())
                .validate()
                .is_err());
        }
    }
}
