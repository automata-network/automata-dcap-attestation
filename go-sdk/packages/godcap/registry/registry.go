package registry

import (
	_ "embed"
	"fmt"
	"path/filepath"
	"strconv"
	"sync"

	deployment "github.com/automata-network/automata-dcap-attestation/rust-crates/libraries/network-registry/deployment"
)

//go:embed metadata.json
var metadataJSON []byte

var (
	registryOnce     sync.Once
	networks         map[string]*Network  // key -> Network
	networksByChainID map[uint64]*Network // chainID -> Network
	defaultNetworkKey string
	initError        error
)

// initRegistry initializes the network registry from embedded files
func initRegistry() {
	registryOnce.Do(func() {
		networks = make(map[string]*Network)
		networksByChainID = make(map[uint64]*Network)

		// Parse metadata
		metadataMap, defaultKey, err := parseMetadata(metadataJSON)
		if err != nil {
			initError = fmt.Errorf("failed to parse metadata: %w", err)
			return
		}
		defaultNetworkKey = defaultKey

		// Load each network's deployment files
		for key, meta := range metadataMap {
			chainIDStr := strconv.FormatUint(meta.ChainID, 10)

			// Read PCCS deployment from shared deployment package
			pccsPath := filepath.Join("current", chainIDStr, "onchain_pccs.json")
			pccsData, err := deployment.CurrentFS.ReadFile(pccsPath)
			if err != nil {
				// Network might not have deployment yet, skip
				continue
			}

			// Read DCAP deployment from shared deployment package
			dcapPath := filepath.Join("current", chainIDStr, "dcap.json")
			dcapData, err := deployment.CurrentFS.ReadFile(dcapPath)
			if err != nil {
				// Network might not have DCAP deployment yet, skip
				continue
			}

			// Parse network
			network, err := parseNetwork(key, meta, pccsData, dcapData, VersionV1_1)
			if err != nil {
				continue
			}

			networks[key] = network
			networksByChainID[meta.ChainID] = network
		}
	})
}

// All returns all registered networks
func All() ([]*Network, error) {
	initRegistry()
	if initError != nil {
		return nil, initError
	}

	result := make([]*Network, 0, len(networks))
	for _, n := range networks {
		result = append(result, n)
	}
	return result, nil
}

// ByKey returns a network by its key (e.g., "eth_mainnet")
func ByKey(key string) (*Network, error) {
	initRegistry()
	if initError != nil {
		return nil, initError
	}

	key = normalizeNetworkKey(key)
	if n, ok := networks[key]; ok {
		return n, nil
	}
	return nil, fmt.Errorf("network not found: %s", key)
}

// ByChainID returns a network by its chain ID
func ByChainID(chainID uint64) (*Network, error) {
	initRegistry()
	if initError != nil {
		return nil, initError
	}

	if n, ok := networksByChainID[chainID]; ok {
		return n, nil
	}
	return nil, fmt.Errorf("network not found for chain ID: %d", chainID)
}

// Default returns the default network (automata_testnet)
func Default() (*Network, error) {
	initRegistry()
	if initError != nil {
		return nil, initError
	}

	return ByKey(defaultNetworkKey)
}

// Mainnets returns all mainnet networks
func Mainnets() ([]*Network, error) {
	all, err := All()
	if err != nil {
		return nil, err
	}

	result := make([]*Network, 0)
	for _, n := range all {
		if !n.Testnet {
			result = append(result, n)
		}
	}
	return result, nil
}

// Testnets returns all testnet networks
func Testnets() ([]*Network, error) {
	all, err := All()
	if err != nil {
		return nil, err
	}

	result := make([]*Network, 0)
	for _, n := range all {
		if n.Testnet {
			result = append(result, n)
		}
	}
	return result, nil
}

// Keys returns all network keys
func Keys() ([]string, error) {
	initRegistry()
	if initError != nil {
		return nil, initError
	}

	keys := make([]string, 0, len(networks))
	for k := range networks {
		keys = append(keys, k)
	}
	return keys, nil
}

// ChainIDs returns all chain IDs
func ChainIDs() ([]uint64, error) {
	initRegistry()
	if initError != nil {
		return nil, initError
	}

	ids := make([]uint64, 0, len(networksByChainID))
	for id := range networksByChainID {
		ids = append(ids, id)
	}
	return ids, nil
}

// MustByKey returns a network by key or panics
func MustByKey(key string) *Network {
	n, err := ByKey(key)
	if err != nil {
		panic(err)
	}
	return n
}

// MustByChainID returns a network by chain ID or panics
func MustByChainID(chainID uint64) *Network {
	n, err := ByChainID(chainID)
	if err != nil {
		panic(err)
	}
	return n
}

// MustDefault returns the default network or panics
func MustDefault() *Network {
	n, err := Default()
	if err != nil {
		panic(err)
	}
	return n
}

// Common network accessors for convenience
var (
	EthereumMainnet  = func() *Network { return MustByKey("eth_mainnet") }
	EthereumSepolia  = func() *Network { return MustByKey("eth_sepolia") }
	ArbitrumMainnet  = func() *Network { return MustByKey("arbitrum_mainnet") }
	ArbitrumSepolia  = func() *Network { return MustByKey("arbitrum_sepolia") }
	BaseMainnet      = func() *Network { return MustByKey("base_mainnet") }
	BaseSepolia      = func() *Network { return MustByKey("base_sepolia") }
	OptimismMainnet  = func() *Network { return MustByKey("op_mainnet") }
	OptimismSepolia  = func() *Network { return MustByKey("op_sepolia") }
	PolygonMainnet   = func() *Network { return MustByKey("polygon_mainnet") }
	PolygonAmoy      = func() *Network { return MustByKey("polygon_amoy") }
	BnbMainnet       = func() *Network { return MustByKey("bnb_mainnet") }
	BnbTestnet       = func() *Network { return MustByKey("bnb_testnet") }
	AvalancheMainnet = func() *Network { return MustByKey("avax_mainnet") }
	AvalancheFuji    = func() *Network { return MustByKey("avax_fuji") }
	AutomataMainnet  = func() *Network { return MustByKey("automata_mainnet") }
	AutomataTestnet  = func() *Network { return MustByKey("automata_testnet") }
	WorldMainnet     = func() *Network { return MustByKey("world_mainnet") }
	WorldSepolia     = func() *Network { return MustByKey("world_sepolia") }
)
