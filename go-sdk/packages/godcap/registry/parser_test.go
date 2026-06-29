package registry

import (
	"testing"

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

func TestNetworkGetFmspcTcbDaoAddressPrefersHoodiVersionedV2(t *testing.T) {
	network := MustByKey("eth_hoodi")
	tests := map[uint32]string{
		19: "0x74A0b849030BC8afaAfFf8F46126E3c13E365C7b",
		20: "0x34cE5cfD6472c5759cC9451ed2Cb13A0b2c8d1f3",
		21: "0xf5536eB1Aa53CF9e1cfA11498749f151278D04bf",
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
