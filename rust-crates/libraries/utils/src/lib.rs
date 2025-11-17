//! Utility types and functions for Automata DCAP tooling.
//!
//! This crate provides common functionality used across the DCAP ecosystem, including:
//! - Version management for DCAP deployments
//! - Quote parsing and handling utilities
//! - Data structure parsers for verified outputs

/// Quote reading and hex parsing utilities.
pub mod quote;
/// Parser utilities for DCAP data structures.
pub mod parser;
/// Version type for DCAP deployments (auto-generated).
pub mod version;

// Re-export commonly used types
pub use version::Version;
