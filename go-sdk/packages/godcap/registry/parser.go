package registry

import (
	"encoding/json"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

// NetworkMetadata represents the metadata from metadata.toml (as JSON)
type NetworkMetadata struct {
	Name            string   `json:"name"`
	ChainID         uint64   `json:"chain_id"`
	Testnet         bool     `json:"testnet"`
	RpcEndpoints    []string `json:"rpc_endpoints"`
	GasPriceHintWei *uint64  `json:"gas_price_hint_wei,omitempty"`
	BlockExplorers  []string `json:"block_explorers,omitempty"`
	DcapPortal      string   `json:"dcap_portal,omitempty"`
}

// PccsDeployment represents the onchain_pccs.json structure
type PccsDeployment map[string]string

// DcapDeployment represents the dcap.json structure
type DcapDeployment map[string]string

// parsePccsDeployment parses the PCCS deployment JSON and extracts contract addresses
func parsePccsDeployment(data []byte) (*PccsContracts, error) {
	var deployment PccsDeployment
	if err := json.Unmarshal(data, &deployment); err != nil {
		return nil, fmt.Errorf("failed to parse PCCS deployment: %w", err)
	}

	contracts := &PccsContracts{
		EnclaveIdDao: VersionedDao{Versioned: make(map[uint32]common.Address)},
		FmspcTcbDao:  VersionedDao{Versioned: make(map[uint32]common.Address)},
	}

	// Regex to extract TCB eval number from versioned DAO keys
	versionedEnclaveIdRegex := regexp.MustCompile(`^AutomataEnclaveIdentityDaoVersioned_tcbeval_(\d+)$`)
	versionedFmspcTcbRegex := regexp.MustCompile(`^AutomataFmspcTcbDaoVersioned_tcbeval_(\d+)$`)

	for key, addrStr := range deployment {
		addr := common.HexToAddress(addrStr)

		switch {
		// Non-versioned base DAOs (used as fallback/legacy)
		case key == "AutomataEnclaveIdentityDao":
			// Store with key 0 as sentinel for legacy/default
			if len(contracts.EnclaveIdDao.Versioned) == 0 {
				contracts.EnclaveIdDao.Versioned[0] = addr
			}
		case key == "AutomataFmspcTcbDao":
			if len(contracts.FmspcTcbDao.Versioned) == 0 {
				contracts.FmspcTcbDao.Versioned[0] = addr
			}

		// Versioned DAOs
		case versionedEnclaveIdRegex.MatchString(key):
			matches := versionedEnclaveIdRegex.FindStringSubmatch(key)
			if len(matches) == 2 {
				evalNum, _ := strconv.ParseUint(matches[1], 10, 32)
				contracts.EnclaveIdDao.Versioned[uint32(evalNum)] = addr
			}
		case versionedFmspcTcbRegex.MatchString(key):
			matches := versionedFmspcTcbRegex.FindStringSubmatch(key)
			if len(matches) == 2 {
				evalNum, _ := strconv.ParseUint(matches[1], 10, 32)
				contracts.FmspcTcbDao.Versioned[uint32(evalNum)] = addr
			}

		// Non-versioned contracts
		case key == "AutomataPcsDao":
			contracts.PcsDao = addr
		case key == "AutomataPckDao":
			contracts.PckDao = addr
		case key == "AutomataTcbEvalDao":
			contracts.TcbEvalDao = addr
		}
	}

	// If we have versioned entries, remove the sentinel 0 entry
	// (it was just used for the non-versioned base address)
	if len(contracts.EnclaveIdDao.Versioned) > 1 {
		delete(contracts.EnclaveIdDao.Versioned, 0)
	}
	if len(contracts.FmspcTcbDao.Versioned) > 1 {
		delete(contracts.FmspcTcbDao.Versioned, 0)
	}

	return contracts, nil
}

// parseDcapDeployment parses the DCAP deployment JSON and extracts contract addresses
func parseDcapDeployment(data []byte) (*DcapContracts, error) {
	var deployment DcapDeployment
	if err := json.Unmarshal(data, &deployment); err != nil {
		return nil, fmt.Errorf("failed to parse DCAP deployment: %w", err)
	}

	contracts := &DcapContracts{}

	for key, addrStr := range deployment {
		addr := common.HexToAddress(addrStr)

		switch key {
		case "AutomataDcapAttestationFee":
			contracts.DcapAttestationFee = addr
		case "PCCSRouter":
			contracts.PccsRouter = addr
		case "V3QuoteVerifier":
			contracts.V3QuoteVerifier = addr
		case "V4QuoteVerifier":
			contracts.V4QuoteVerifier = addr
		case "V5QuoteVerifier":
			contracts.V5QuoteVerifier = addr
		}
	}

	return contracts, nil
}

// parseNetwork creates a Network from metadata and deployment data
func parseNetwork(
	key string,
	metadata *NetworkMetadata,
	pccsData []byte,
	dcapData []byte,
	version Version,
) (*Network, error) {
	pccs, err := parsePccsDeployment(pccsData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PCCS for %s: %w", key, err)
	}

	dcap, err := parseDcapDeployment(dcapData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DCAP for %s: %w", key, err)
	}

	// Add DcapPortal from metadata if present
	if metadata.DcapPortal != "" {
		dcap.DcapPortal = common.HexToAddress(metadata.DcapPortal)
	}

	var gasPriceHint *big.Int
	if metadata.GasPriceHintWei != nil {
		gasPriceHint = new(big.Int).SetUint64(*metadata.GasPriceHintWei)
	}

	return &Network{
		Key:             key,
		DisplayName:     metadata.Name,
		ChainID:         metadata.ChainID,
		Testnet:         metadata.Testnet,
		RpcEndpoints:    metadata.RpcEndpoints,
		BlockExplorers:  metadata.BlockExplorers,
		GasPriceHintWei: gasPriceHint,
		Version:         version,
		Contracts: Contracts{
			Pccs: *pccs,
			Dcap: *dcap,
		},
	}, nil
}

// MetadataConfig represents the full metadata.toml converted to JSON
type MetadataConfig map[string]json.RawMessage

// parseMetadata parses the metadata JSON (converted from TOML)
func parseMetadata(data []byte) (map[string]*NetworkMetadata, string, error) {
	var config MetadataConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, "", fmt.Errorf("failed to parse metadata: %w", err)
	}

	networks := make(map[string]*NetworkMetadata)
	var defaultNetwork string

	for key, raw := range config {
		if key == "default" {
			var defaultConfig struct {
				NetworkKey string `json:"network_key"`
			}
			if err := json.Unmarshal(raw, &defaultConfig); err == nil {
				defaultNetwork = defaultConfig.NetworkKey
			}
			continue
		}

		var meta NetworkMetadata
		if err := json.Unmarshal(raw, &meta); err != nil {
			continue // Skip invalid entries
		}
		networks[key] = &meta
	}

	return networks, defaultNetwork, nil
}

// chainIDToKey creates a mapping from chain ID to network key
func chainIDToKey(networks map[string]*NetworkMetadata) map[uint64]string {
	result := make(map[uint64]string)
	for key, meta := range networks {
		result[meta.ChainID] = key
	}
	return result
}

// normalizeNetworkKey converts various network key formats to the canonical form
func normalizeNetworkKey(key string) string {
	// Handle common variations
	key = strings.ToLower(key)
	key = strings.ReplaceAll(key, "-", "_")
	key = strings.ReplaceAll(key, " ", "_")
	return key
}
