use std::path::PathBuf;

/// Configuration for Pico zkVM proving
#[derive(Debug, Clone)]
pub struct PicoConfig {
    /// Path to the directory containing EVM proof artifacts (vm_pk, vm_vk, constraints.json)
    pub artifacts_path: PathBuf,

    /// Field type for proving backend (e.g., "kb" for KoalaBear, "bb" for BabyBear)
    /// Default: "kb" (KoalaBear)
    pub field_type: String,
}

impl Default for PicoConfig {
    fn default() -> Self {
        Self {
            // Default to bundled artifacts in the crate
            artifacts_path: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("src/pico/artifacts"),
            field_type: "kb".to_string(),
        }
    }
}

impl PicoConfig {
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
