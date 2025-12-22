// Package deployment provides embedded deployment files for the DCAP network registry.
// This package is shared between Rust and Go SDKs.
package deployment

import "embed"

//go:embed current
var CurrentFS embed.FS

//go:embed v1.0
var V1_0FS embed.FS
