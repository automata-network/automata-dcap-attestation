package registry

import (
	"context"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

// Version represents the DCAP deployment version
type Version string

const (
	VersionV1_0 Version = "v1.0"
	VersionV1_1 Version = "v1.1" // Current version with versioned DAOs
)

// VersionedDao maps TCB evaluation numbers to contract addresses
// For v1.0, there's a single entry with key 0 (sentinel)
// For v1.1, there are multiple entries keyed by TCB eval number (17, 18, 19, 20, etc.)
type VersionedDao struct {
	Versioned map[uint32]common.Address
}

// GetAddress returns the contract address for a given TCB evaluation number
func (v *VersionedDao) GetAddress(tcbEvalNum uint32) (common.Address, error) {
	if addr, ok := v.Versioned[tcbEvalNum]; ok {
		return addr, nil
	}
	return common.Address{}, fmt.Errorf("no address found for tcbEvalNum %d", tcbEvalNum)
}

// IsV1_0 returns true if this is a v1.0 style DAO (single address with key 0)
func (v *VersionedDao) IsV1_0() bool {
	if len(v.Versioned) == 1 {
		_, ok := v.Versioned[0]
		return ok
	}
	return false
}

// AvailableVersions returns all available TCB evaluation numbers
func (v *VersionedDao) AvailableVersions() []uint32 {
	versions := make([]uint32, 0, len(v.Versioned))
	for k := range v.Versioned {
		versions = append(versions, k)
	}
	return versions
}

// PccsContracts holds all PCCS-related contract addresses
type PccsContracts struct {
	// Versioned DAOs - support multiple TCB evaluation versions
	EnclaveIdDao VersionedDao
	FmspcTcbDao  VersionedDao

	// Non-versioned contracts
	PcsDao     common.Address
	PckDao     common.Address
	TcbEvalDao common.Address // Only in v1.1, zero address in v1.0
}

// DcapContracts holds all DCAP attestation contract addresses
type DcapContracts struct {
	DcapAttestationFee common.Address // AutomataDcapAttestationFee - base attestation with fee
	DcapPortal         common.Address // Optional
	PccsRouter         common.Address
	V3QuoteVerifier    common.Address
	V4QuoteVerifier    common.Address
	V5QuoteVerifier    common.Address
}

// Contracts holds all contract addresses for a network
type Contracts struct {
	Pccs PccsContracts
	Dcap DcapContracts
}

// Network represents a blockchain network configuration
type Network struct {
	Key             string   // Unique identifier (e.g., "eth_mainnet")
	DisplayName     string   // Human-readable name (e.g., "Ethereum Mainnet")
	ChainID         uint64   // EVM chain ID
	Testnet         bool     // Whether this is a testnet
	RpcEndpoints    []string // Ordered by preference
	BlockExplorers  []string // Block explorer URLs
	GasPriceHintWei *big.Int // Optional gas price hint
	Version         Version  // Deployment version (v1.0 or v1.1)
	Contracts       Contracts
}

// DefaultRpcUrl returns the first (preferred) RPC endpoint
func (n *Network) DefaultRpcUrl() string {
	if len(n.RpcEndpoints) > 0 {
		return n.RpcEndpoints[0]
	}
	return ""
}

// DefaultExplorer returns the first block explorer URL
func (n *Network) DefaultExplorer() string {
	if len(n.BlockExplorers) > 0 {
		return n.BlockExplorers[0]
	}
	return ""
}

// SupportsVersionedDaos returns true if this network uses v1.1 versioned DAOs
func (n *Network) SupportsVersionedDaos() bool {
	return n.Version == VersionV1_1 && n.Contracts.Pccs.TcbEvalDao != (common.Address{})
}

// ContractKind represents the type of contract to resolve
type ContractKind int

const (
	ContractEnclaveIdDao ContractKind = iota
	ContractFmspcTcbDao
	ContractPcsDao
	ContractPckDao
	ContractTcbEvalDao
	ContractDcapAttestationFee
	ContractPccsRouter
	ContractV3QuoteVerifier
	ContractV4QuoteVerifier
	ContractV5QuoteVerifier
)

// TcbEvalDaoInterface is the interface for querying standard TCB eval number
type TcbEvalDaoInterface interface {
	Standard(opts *bind.CallOpts, tcbId *big.Int) (*big.Int, error)
}

// ResolveContractAddress resolves a contract address, handling versioned DAOs
func (n *Network) ResolveContractAddress(
	ctx context.Context,
	contract ContractKind,
	tcbEvalNum *uint32,
	tcbId *uint8,
	client *ethclient.Client,
	tcbEvalDao TcbEvalDaoInterface,
) (common.Address, error) {
	switch contract {
	case ContractEnclaveIdDao:
		return n.resolveVersionedDao(&n.Contracts.Pccs.EnclaveIdDao, tcbEvalNum, tcbId, ctx, tcbEvalDao)
	case ContractFmspcTcbDao:
		return n.resolveVersionedDao(&n.Contracts.Pccs.FmspcTcbDao, tcbEvalNum, tcbId, ctx, tcbEvalDao)
	case ContractPcsDao:
		return n.Contracts.Pccs.PcsDao, nil
	case ContractPckDao:
		return n.Contracts.Pccs.PckDao, nil
	case ContractTcbEvalDao:
		return n.Contracts.Pccs.TcbEvalDao, nil
	case ContractDcapAttestationFee:
		return n.Contracts.Dcap.DcapAttestationFee, nil
	case ContractPccsRouter:
		return n.Contracts.Dcap.PccsRouter, nil
	case ContractV3QuoteVerifier:
		return n.Contracts.Dcap.V3QuoteVerifier, nil
	case ContractV4QuoteVerifier:
		return n.Contracts.Dcap.V4QuoteVerifier, nil
	case ContractV5QuoteVerifier:
		return n.Contracts.Dcap.V5QuoteVerifier, nil
	default:
		return common.Address{}, fmt.Errorf("unknown contract kind: %d", contract)
	}
}

func (n *Network) resolveVersionedDao(
	dao *VersionedDao,
	tcbEvalNum *uint32,
	tcbId *uint8,
	ctx context.Context,
	tcbEvalDao TcbEvalDaoInterface,
) (common.Address, error) {
	// If v1.0 style, just return the single address
	if dao.IsV1_0() {
		return dao.Versioned[0], nil
	}

	// If explicit version provided, use it
	if tcbEvalNum != nil {
		return dao.GetAddress(*tcbEvalNum)
	}

	// Try to auto-detect using TcbEvalDao.standard()
	if tcbEvalDao != nil && tcbId != nil {
		standard, err := tcbEvalDao.Standard(&bind.CallOpts{Context: ctx}, big.NewInt(int64(*tcbId)))
		if err == nil && standard != nil {
			evalNum := uint32(standard.Uint64())
			return dao.GetAddress(evalNum)
		}
	}

	return common.Address{}, fmt.Errorf("cannot resolve versioned DAO address: tcbEvalNum or tcbEvalDao required")
}

// GetEnclaveIdDaoAddress returns the EnclaveIdDao address for a specific TCB eval version
func (n *Network) GetEnclaveIdDaoAddress(tcbEvalNum uint32) (common.Address, error) {
	return n.Contracts.Pccs.EnclaveIdDao.GetAddress(tcbEvalNum)
}

// GetFmspcTcbDaoAddress returns the FmspcTcbDao address for a specific TCB eval version
func (n *Network) GetFmspcTcbDaoAddress(tcbEvalNum uint32) (common.Address, error) {
	return n.Contracts.Pccs.FmspcTcbDao.GetAddress(tcbEvalNum)
}
