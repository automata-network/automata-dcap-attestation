package registry

import (
	"encoding/json"
	"path/filepath"
	"strconv"
	"testing"

	deployment "github.com/automata-network/automata-dcap-attestation/rust-crates/libraries/network-registry/deployment"
	"github.com/ethereum/go-ethereum/common"
)

func TestParsePccsDeploymentPrefersFmspcTcbDaoVersionedV2(t *testing.T) {
	const (
		v1Address = "0x1111111111111111111111111111111111111111"
		v2Address = "0x2222222222222222222222222222222222222222"
	)
	deployment := []byte(`{
		"AutomataFmspcTcbDaoVersioned_tcbeval_19": "` + v1Address + `",
		"AutomataFmspcTcbDaoVersionedV2_tcbeval_19": "` + v2Address + `"
	}`)

	contracts, err := parsePccsDeployment(deployment)
	if err != nil {
		t.Fatalf("parsePccsDeployment: %v", err)
	}

	got, err := contracts.FmspcTcbDao.GetAddress(19)
	if err != nil {
		t.Fatalf("GetAddress(19): %v", err)
	}
	if want := common.HexToAddress(v2Address); got != want {
		t.Fatalf("GetAddress(19) = %s, want V2 address %s", got.Hex(), want.Hex())
	}
}

func TestParsePccsDeploymentFallsBackToFmspcTcbDaoVersioned(t *testing.T) {
	const v1Address = "0x1111111111111111111111111111111111111111"
	deployment := []byte(`{
		"AutomataFmspcTcbDaoVersioned_tcbeval_19": "` + v1Address + `"
	}`)

	contracts, err := parsePccsDeployment(deployment)
	if err != nil {
		t.Fatalf("parsePccsDeployment: %v", err)
	}

	got, err := contracts.FmspcTcbDao.GetAddress(19)
	if err != nil {
		t.Fatalf("GetAddress(19): %v", err)
	}
	if want := common.HexToAddress(v1Address); got != want {
		t.Fatalf("GetAddress(19) = %s, want fallback V1 address %s", got.Hex(), want.Hex())
	}
}

func TestParsePccsDeploymentPrefersCrlV2(t *testing.T) {
	deployment := []byte(`{
		"AutomataEnclaveIdentityDaoVersioned_tcbeval_20": "0x1111111111111111111111111111111111111111",
		"AutomataEnclaveIdentityDaoVersionedCrlV2_tcbeval_20": "0x2222222222222222222222222222222222222222",
		"AutomataFmspcTcbDaoVersioned_tcbeval_20": "0x3333333333333333333333333333333333333333",
		"AutomataFmspcTcbDaoVersionedV2_tcbeval_20": "0x4444444444444444444444444444444444444444",
		"AutomataFmspcTcbDaoVersionedV2CrlV2_tcbeval_20": "0x5555555555555555555555555555555555555555",
		"AutomataTcbEvalDao": "0x6666666666666666666666666666666666666666",
		"AutomataTcbEvalDaoCrlV2": "0x7777777777777777777777777777777777777777",
		"AutomataPckDao": "0x8888888888888888888888888888888888888888",
		"AutomataPckDaoV2": "0x9999999999999999999999999999999999999999",
		"AutomataPcsDao": "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"AutomataPcsDaoV2": "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	}`)

	contracts, err := parsePccsDeployment(deployment)
	if err != nil {
		t.Fatalf("parsePccsDeployment: %v", err)
	}

	if got, err := contracts.EnclaveIdDao.GetAddress(20); err != nil ||
		got != common.HexToAddress("0x2222222222222222222222222222222222222222") {
		t.Fatalf("CRL V2 Enclave Identity address = %s, err = %v", got.Hex(), err)
	}
	if got, err := contracts.FmspcTcbDao.GetAddress(20); err != nil ||
		got != common.HexToAddress("0x5555555555555555555555555555555555555555") {
		t.Fatalf("CRL V2 FMSPC address = %s, err = %v", got.Hex(), err)
	}
	if want := common.HexToAddress("0x7777777777777777777777777777777777777777"); contracts.TcbEvalDao != want {
		t.Fatalf("TcbEvalDao = %s, want %s", contracts.TcbEvalDao.Hex(), want.Hex())
	}
	if want := common.HexToAddress("0x9999999999999999999999999999999999999999"); contracts.PckDao != want {
		t.Fatalf("PckDao = %s, want %s", contracts.PckDao.Hex(), want.Hex())
	}
	if want := common.HexToAddress("0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"); contracts.PcsDao != want {
		t.Fatalf("PcsDao = %s, want %s", contracts.PcsDao.Hex(), want.Hex())
	}
}

func TestParsePccsDeploymentFallsBackWhenCrlV2IsAbsent(t *testing.T) {
	deployment := []byte(`{
		"AutomataEnclaveIdentityDaoVersioned_tcbeval_20": "0x1111111111111111111111111111111111111111",
		"AutomataFmspcTcbDaoVersionedV2_tcbeval_20": "0x2222222222222222222222222222222222222222",
		"AutomataTcbEvalDao": "0x3333333333333333333333333333333333333333",
		"AutomataPckDao": "0x4444444444444444444444444444444444444444",
		"AutomataPcsDao": "0x5555555555555555555555555555555555555555"
	}`)

	contracts, err := parsePccsDeployment(deployment)
	if err != nil {
		t.Fatalf("parsePccsDeployment: %v", err)
	}

	if got, err := contracts.EnclaveIdDao.GetAddress(20); err != nil ||
		got != common.HexToAddress("0x1111111111111111111111111111111111111111") {
		t.Fatalf("fallback Enclave Identity address = %s, err = %v", got.Hex(), err)
	}
	if got, err := contracts.FmspcTcbDao.GetAddress(20); err != nil ||
		got != common.HexToAddress("0x2222222222222222222222222222222222222222") {
		t.Fatalf("fallback FMSPC address = %s, err = %v", got.Hex(), err)
	}
	if want := common.HexToAddress("0x3333333333333333333333333333333333333333"); contracts.TcbEvalDao != want {
		t.Fatalf("TcbEvalDao = %s, want %s", contracts.TcbEvalDao.Hex(), want.Hex())
	}
	if want := common.HexToAddress("0x4444444444444444444444444444444444444444"); contracts.PckDao != want {
		t.Fatalf("PckDao = %s, want %s", contracts.PckDao.Hex(), want.Hex())
	}
	if want := common.HexToAddress("0x5555555555555555555555555555555555555555"); contracts.PcsDao != want {
		t.Fatalf("PcsDao = %s, want %s", contracts.PcsDao.Hex(), want.Hex())
	}
}

func TestNetworkGetFmspcTcbDaoAddressPrefersCrlV2(t *testing.T) {
	network := MustByKey("eth_hoodi")
	tests := map[uint32]string{
		19: "0x74A0b849030BC8afaAfFf8F46126E3c13E365C7b",
		20: "0xe49D3c73852aDe8Ad37E7A1072b6bb68D913FDc1",
		21: "0x0dEa24Cc559A785e109c2e31B854700bBeFA1397",
	}

	for evalNum, wantAddress := range tests {
		got, err := network.GetFmspcTcbDaoAddress(evalNum)
		if err != nil {
			t.Fatalf("GetFmspcTcbDaoAddress(%d): %v", evalNum, err)
		}
		if want := common.HexToAddress(wantAddress); got != want {
			t.Fatalf("GetFmspcTcbDaoAddress(%d) = %s, want V2 address %s", evalNum, got.Hex(), want.Hex())
		}
	}
}

func TestCurrentRegistryPrefersCrlV2AndPreservesLegacyFallbacks(t *testing.T) {
	networks, err := All()
	if err != nil {
		t.Fatalf("All: %v", err)
	}

	crlV2Networks := 0
	legacyNetworks := 0
	for _, network := range networks {
		deploymentPath := filepath.Join(
			"current",
			strconv.FormatUint(network.ChainID, 10),
			"onchain_pccs.json",
		)
		deploymentJSON, err := deployment.CurrentFS.ReadFile(deploymentPath)
		if err != nil {
			t.Fatalf("read %s: %v", deploymentPath, err)
		}

		var addresses PccsDeployment
		if err := json.Unmarshal(deploymentJSON, &addresses); err != nil {
			t.Fatalf("parse %s: %v", deploymentPath, err)
		}

		if _, upgraded := addresses["AutomataPcsDaoV2"]; upgraded {
			crlV2Networks++
			if want := common.HexToAddress(addresses["AutomataPcsDaoV2"]); network.Contracts.Pccs.PcsDao != want {
				t.Fatalf("%s PcsDao = %s, want %s", network.Key, network.Contracts.Pccs.PcsDao.Hex(), want.Hex())
			}
			if want := common.HexToAddress(addresses["AutomataPckDaoV2"]); network.Contracts.Pccs.PckDao != want {
				t.Fatalf("%s PckDao = %s, want %s", network.Key, network.Contracts.Pccs.PckDao.Hex(), want.Hex())
			}
			if want := common.HexToAddress(addresses["AutomataTcbEvalDaoCrlV2"]); network.Contracts.Pccs.TcbEvalDao != want {
				t.Fatalf("%s TcbEvalDao = %s, want %s", network.Key, network.Contracts.Pccs.TcbEvalDao.Hex(), want.Hex())
			}

			for evalNum, enclaveKey := range map[uint32]string{
				20: "AutomataEnclaveIdentityDaoVersionedCrlV2_tcbeval_20",
				21: "AutomataEnclaveIdentityDaoVersionedCrlV2_tcbeval_21",
			} {
				got, err := network.Contracts.Pccs.EnclaveIdDao.GetAddress(evalNum)
				if err != nil {
					t.Fatalf("%s Enclave Identity evaluation %d: %v", network.Key, evalNum, err)
				}
				if want := common.HexToAddress(addresses[enclaveKey]); got != want {
					t.Fatalf("%s Enclave Identity evaluation %d = %s, want %s", network.Key, evalNum, got.Hex(), want.Hex())
				}
			}

			for evalNum, fmspcKey := range map[uint32]string{
				20: "AutomataFmspcTcbDaoVersionedV2CrlV2_tcbeval_20",
				21: "AutomataFmspcTcbDaoVersionedV2CrlV2_tcbeval_21",
			} {
				got, err := network.Contracts.Pccs.FmspcTcbDao.GetAddress(evalNum)
				if err != nil {
					t.Fatalf("%s FMSPC evaluation %d: %v", network.Key, evalNum, err)
				}
				if want := common.HexToAddress(addresses[fmspcKey]); got != want {
					t.Fatalf("%s FMSPC evaluation %d = %s, want %s", network.Key, evalNum, got.Hex(), want.Hex())
				}
			}
		} else {
			legacyNetworks++
			if want := common.HexToAddress(addresses["AutomataPcsDao"]); network.Contracts.Pccs.PcsDao != want {
				t.Fatalf("%s legacy PcsDao = %s, want %s", network.Key, network.Contracts.Pccs.PcsDao.Hex(), want.Hex())
			}
			if want := common.HexToAddress(addresses["AutomataPckDao"]); network.Contracts.Pccs.PckDao != want {
				t.Fatalf("%s legacy PckDao = %s, want %s", network.Key, network.Contracts.Pccs.PckDao.Hex(), want.Hex())
			}
			if want := common.HexToAddress(addresses["AutomataTcbEvalDao"]); network.Contracts.Pccs.TcbEvalDao != want {
				t.Fatalf("%s legacy TcbEvalDao = %s, want %s", network.Key, network.Contracts.Pccs.TcbEvalDao.Hex(), want.Hex())
			}
			if _, err := network.Contracts.Pccs.EnclaveIdDao.GetAddress(21); err == nil {
				t.Fatalf("%s unexpectedly supports Enclave Identity evaluation 21", network.Key)
			}
			if _, err := network.Contracts.Pccs.FmspcTcbDao.GetAddress(21); err == nil {
				t.Fatalf("%s unexpectedly supports FMSPC evaluation 21", network.Key)
			}
		}
	}

	if crlV2Networks != 25 {
		t.Fatalf("CRL V2 network count = %d, want 25", crlV2Networks)
	}
	if legacyNetworks != 3 {
		t.Fatalf("legacy network count = %d, want 3", legacyNetworks)
	}
}
