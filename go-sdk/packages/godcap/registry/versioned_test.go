package registry

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestV2RequiresSeparateFeeKey(t *testing.T) {
	legacy := []byte(`{"AutomataDcapAttestationFee":"0x1111111111111111111111111111111111111111"}`)
	meta := &NetworkMetadata{ChainID: 1}
	if _, err := parseNetwork("test", meta, []byte(`{}`), legacy, VersionV2_0); err == nil {
		t.Fatal("V2 silently selected a legacy Fee address")
	}
	both := []byte(`{"AutomataDcapAttestationFee":"0x1111111111111111111111111111111111111111","AutomataDcapAttestationFeeV2":"0x2222222222222222222222222222222222222222"}`)
	network, err := parseNetwork("test", meta, []byte(`{}`), both, VersionV2_0)
	if err != nil {
		t.Fatal(err)
	}
	if network.Contracts.Dcap.DcapAttestationFee != common.HexToAddress("0x1111111111111111111111111111111111111111") ||
		network.Contracts.Dcap.DcapAttestationFeeV2 != common.HexToAddress("0x2222222222222222222222222222222222222222") {
		t.Fatal("versioned Fee keys were conflated")
	}
}

func TestFrozenV1LookupDoesNotNeedV2Deployment(t *testing.T) {
	legacy, err := ByChainIDVersion(1, VersionV1_1)
	if err != nil {
		t.Fatal(err)
	}
	if legacy.Version != VersionV1_1 || legacy.Contracts.Dcap.DcapAttestationFee == (common.Address{}) {
		t.Fatal("missing frozen legacy deployment")
	}
	if _, err := ByChainIDVersion(1, Version("unsupported")); err == nil {
		t.Fatal("unsupported version fell back to legacy")
	}
}
