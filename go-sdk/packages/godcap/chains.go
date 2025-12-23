package godcap

import (
	"github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/registry"
)

// Network is an alias for registry.Network for convenience
type Network = registry.Network

// Re-export registry functions for convenience
var (
	// GetNetworkByKey returns a network by its key (e.g., "eth_mainnet")
	GetNetworkByKey = registry.ByKey

	// GetNetworkByChainID returns a network by its chain ID
	GetNetworkByChainID = registry.ByChainID

	// GetDefaultNetwork returns the default network (automata_testnet)
	GetDefaultNetwork = registry.Default

	// GetAllNetworks returns all registered networks
	GetAllNetworks = registry.All

	// GetMainnets returns all mainnet networks
	GetMainnets = registry.Mainnets

	// GetTestnets returns all testnet networks
	GetTestnets = registry.Testnets
)

// Common network accessors
var (
	NetworkEthereumMainnet  = registry.EthereumMainnet
	NetworkEthereumSepolia  = registry.EthereumSepolia
	NetworkArbitrumMainnet  = registry.ArbitrumMainnet
	NetworkArbitrumSepolia  = registry.ArbitrumSepolia
	NetworkBaseMainnet      = registry.BaseMainnet
	NetworkBaseSepolia      = registry.BaseSepolia
	NetworkOptimismMainnet  = registry.OptimismMainnet
	NetworkOptimismSepolia  = registry.OptimismSepolia
	NetworkPolygonMainnet   = registry.PolygonMainnet
	NetworkPolygonAmoy      = registry.PolygonAmoy
	NetworkBnbMainnet       = registry.BnbMainnet
	NetworkBnbTestnet       = registry.BnbTestnet
	NetworkAvalancheMainnet = registry.AvalancheMainnet
	NetworkAvalancheFuji    = registry.AvalancheFuji
	NetworkAutomataMainnet  = registry.AutomataMainnet
	NetworkAutomataTestnet  = registry.AutomataTestnet
	NetworkWorldMainnet     = registry.WorldMainnet
	NetworkWorldSepolia     = registry.WorldSepolia
)
