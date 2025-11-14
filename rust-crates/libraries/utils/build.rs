use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use proc_macro2::{Ident, Span, TokenStream};
use quote::quote;
use toml::Value;

fn main() {
    // Find the workspace root by looking for version.toml
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("Could not find workspace root");

    let version_toml_path = workspace_root.join("version.toml");

    // Tell cargo to rerun if version.toml changes
    println!("cargo:rerun-if-changed={}", version_toml_path.display());

    // Read and parse version.toml
    let version_toml_content =
        fs::read_to_string(&version_toml_path).expect("Failed to read version.toml");

    let version_config: Value =
        toml::from_str(&version_toml_content).expect("Failed to parse version.toml");

    // Extract supported versions
    let supported_versions = version_config
        .get("metadata")
        .and_then(|m| m.get("supported"))
        .and_then(|s| s.as_array())
        .expect("Failed to get supported versions from version.toml");

    let versions: Vec<String> = supported_versions
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();

    // Extract current version
    let current_version = version_config
        .get("metadata")
        .and_then(|m| m.get("current"))
        .and_then(|c| c.as_str())
        .map(|s| s.to_string());

    // Extract version configurations
    let version_configs = version_config
        .get("versions")
        .and_then(|v| v.as_table())
        .expect("Failed to get version configurations");

    // Generate the version.rs file
    let generated_code = generate_version_module(&versions, version_configs, current_version.as_deref());

    // Write to src/version.rs
    let out_path = manifest_dir.join("src/version.rs");
    fs::write(&out_path, generated_code.to_string()).expect("Failed to write generated version.rs");

    // Format the generated file with rustfmt
    let _ = Command::new("rustfmt")
        .arg(&out_path)
        .output();
}

fn generate_version_module(
    versions: &[String],
    configs: &toml::map::Map<String, Value>,
    current_version: Option<&str>,
) -> TokenStream {
    // Convert version strings to enum variant names (e.g., "v1.0" -> "V1_0")
    let variants: Vec<(String, Ident)> = versions
        .iter()
        .map(|v| {
            let variant_name = v.replace(".", "_").replace("-", "_").to_uppercase();
            (v.clone(), Ident::new(&variant_name, Span::call_site()))
        })
        .collect();

    // Generate enum variants with serde rename attributes
    let enum_variants: Vec<TokenStream> = variants
        .iter()
        .map(|(version_str, variant)| {
            quote! {
                #[serde(rename = #version_str)]
                #variant
            }
        })
        .collect();

    // Generate the all() method body
    let all_variants: Vec<&Ident> = variants.iter().map(|(_, v)| v).collect();

    // Generate the as_str() match arms
    let as_str_arms: Vec<TokenStream> = variants
        .iter()
        .map(|(version_str, variant)| {
            quote! {
                Version::#variant => #version_str
            }
        })
        .collect();

    // Generate the supports_tcb_eval_dao() match arms
    let tcb_eval_arms: Vec<TokenStream> = variants
        .iter()
        .map(|(version_str, variant)| {
            let key = version_str.replace(".", "_");
            let supports = configs
                .get(&key)
                .and_then(|c| c.get("description"))
                .and_then(|d| d.as_str())
                .map(|d| d.contains("TcbEvalDao"))
                .unwrap_or(false);

            quote! {
                Version::#variant => #supports
            }
        })
        .collect();

    // Generate the uses_versioned_daos() match arms
    let versioned_daos_arms: Vec<TokenStream> = variants
        .iter()
        .map(|(version_str, variant)| {
            let key = version_str.replace(".", "_");
            let uses_versioned = configs
                .get(&key)
                .and_then(|c| c.get("description"))
                .and_then(|d| d.as_str())
                .map(|d| d.contains("versioned DAOs") && !d.contains("non-versioned"))
                .unwrap_or(false);

            quote! {
                Version::#variant => #uses_versioned
            }
        })
        .collect();

    // Generate FromStr match arms for different formats
    let mut from_str_arms: Vec<TokenStream> = variants
        .iter()
        .map(|(version_str, variant)| {
            let underscore_version = version_str.replace(".", "_");
            let numeric_version = version_str.trim_start_matches('v');

            quote! {
                #version_str | #underscore_version | #numeric_version => Ok(Version::#variant)
            }
        })
        .collect();

    // Add "current" case that resolves to the current version
    if let Some(current) = current_version {
        if let Some((_, current_variant)) = variants.iter().find(|(v, _)| v == current) {
            from_str_arms.push(quote! {
                "current" => Ok(Version::#current_variant)
            });
        }
    }

    // Generate test cases
    let test_from_str_cases: Vec<TokenStream> = variants
        .iter()
        .map(|(version_str, variant)| {
            let underscore_version = version_str.replace(".", "_");
            let numeric_version = version_str.trim_start_matches('v');

            quote! {
                assert_eq!(Version::from_str(#version_str).unwrap(), Version::#variant);
                assert_eq!(Version::from_str(#underscore_version).unwrap(), Version::#variant);
                assert_eq!(Version::from_str(#numeric_version).unwrap(), Version::#variant);
            }
        })
        .collect();

    let test_tcb_eval_cases: Vec<TokenStream> = variants
        .iter()
        .map(|(version_str, variant)| {
            let key = version_str.replace(".", "_");
            let supports = configs
                .get(&key)
                .and_then(|c| c.get("description"))
                .and_then(|d| d.as_str())
                .map(|d| d.contains("TcbEvalDao"))
                .unwrap_or(false);

            if supports {
                quote! {
                    assert!(Version::#variant.supports_tcb_eval_dao());
                }
            } else {
                quote! {
                    assert!(!Version::#variant.supports_tcb_eval_dao());
                }
            }
        })
        .collect();

    let test_versioned_daos_cases: Vec<TokenStream> = variants
        .iter()
        .map(|(version_str, variant)| {
            let key = version_str.replace(".", "_");
            let uses_versioned = configs
                .get(&key)
                .and_then(|c| c.get("description"))
                .and_then(|d| d.as_str())
                .map(|d| d.contains("versioned DAOs") && !d.contains("non-versioned"))
                .unwrap_or(false);

            if uses_versioned {
                quote! {
                    assert!(Version::#variant.uses_versioned_daos());
                }
            } else {
                quote! {
                    assert!(!Version::#variant.uses_versioned_daos());
                }
            }
        })
        .collect();

    // Generate the complete module
    quote! {
        use serde::{Deserialize, Serialize};
        use std::fmt;
        use std::str::FromStr;

        /// Version enum representing supported DCAP deployment versions
        ///
        /// This module is auto-generated from version.toml at build time.
        /// Do not edit this file manually.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub enum Version {
            #(#enum_variants,)*
        }

        impl Version {
            /// Get all supported versions
            pub fn all() -> Vec<Version> {
                vec![#(Version::#all_variants),*]
            }

            /// Get the version string (e.g., "v1.0")
            pub fn as_str(&self) -> &'static str {
                match self {
                    #(#as_str_arms,)*
                }
            }

            /// Check if this version supports TcbEvalDao
            pub fn supports_tcb_eval_dao(&self) -> bool {
                match self {
                    #(#tcb_eval_arms,)*
                }
            }

            /// Check if this version uses versioned DAOs
            pub fn uses_versioned_daos(&self) -> bool {
                match self {
                    #(#versioned_daos_arms,)*
                }
            }
        }

        impl fmt::Display for Version {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.as_str())
            }
        }

        impl FromStr for Version {
            type Err = anyhow::Error;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    #(#from_str_arms,)*
                    _ => Err(anyhow::anyhow!("Unsupported version: {}", s)),
                }
            }
        }

        #[cfg(test)]
        mod tests {
            use super::*;

            #[test]
            fn test_version_from_str() {
                #(#test_from_str_cases)*
                assert!(Version::from_str("v99.99").is_err());
            }

            #[test]
            fn test_version_tcb_eval_dao() {
                #(#test_tcb_eval_cases)*
            }

            #[test]
            fn test_version_uses_versioned_daos() {
                #(#test_versioned_daos_cases)*
            }
        }
    }
}
