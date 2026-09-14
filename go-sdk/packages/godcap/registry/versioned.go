package registry

import (
	"embed"
	"fmt"
	"strconv"

	deployment "github.com/automata-network/automata-dcap-attestation/rust-crates/libraries/network-registry/deployment"
)

// ByChainIDVersion never falls back from an unpublished V2 deployment to a legacy address.
func ByChainIDVersion(chainID uint64, version Version) (*Network, error) {
	var files embed.FS
	switch version {
	case VersionV1_0:
		files = deployment.V1_0FS
	case VersionV1_1:
		files = deployment.V1_1FS
	case VersionV2_0:
		files = deployment.V2_0FS
	default:
		return nil, fmt.Errorf("unsupported deployment version %s", version)
	}
	metadata, _, err := parseMetadata(metadataJSON)
	if err != nil {
		return nil, err
	}
	for key, meta := range metadata {
		if meta.ChainID != chainID {
			continue
		}
		prefix := string(version) + "/" + strconv.FormatUint(chainID, 10) + "/"
		pccs, err := files.ReadFile(prefix + "onchain_pccs.json")
		if err != nil {
			return nil, err
		}
		dcap, err := files.ReadFile(prefix + "dcap.json")
		if err != nil {
			return nil, err
		}
		return parseNetwork(key, meta, pccs, dcap, version)
	}
	return nil, fmt.Errorf("network %d not found for %s", chainID, version)
}
