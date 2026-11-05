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
	missingRouter := []byte(`{"AutomataDcapAttestationV2":"0x2222222222222222222222222222222222222222","PCCSRouter":"0x3333333333333333333333333333333333333333"}`)
	if _, err := parseNetwork("test", meta, []byte(`{}`), missingRouter, VersionV2_0); err == nil {
		t.Fatal("V2 silently selected a legacy Router")
	}
	both := []byte(`{"AutomataDcapAttestationFee":"0x1111111111111111111111111111111111111111","AutomataDcapAttestationV2":"0x2222222222222222222222222222222222222222","PCCSRouter":"0x3333333333333333333333333333333333333333","PCCSRouterV2":"0x4444444444444444444444444444444444444444"}`)
	network, err := parseNetwork("test", meta, []byte(`{}`), both, VersionV2_0)
	if err != nil {
		t.Fatal(err)
	}
	if network.Contracts.Dcap.DcapAttestationFee != common.HexToAddress("0x1111111111111111111111111111111111111111") ||
		network.Contracts.Dcap.DcapAttestationFeeV2 != common.HexToAddress("0x2222222222222222222222222222222222222222") {
		t.Fatal("versioned Fee keys were conflated")
	}
	if network.Contracts.Dcap.PccsRouter != common.HexToAddress("0x4444444444444444444444444444444444444444") {
		t.Fatal("V2 Router was not selected")
	}
	old, err := parseNetwork("test", meta, []byte(`{}`), both, VersionV1_1)
	if err != nil || old.Contracts.Dcap.PccsRouter != common.HexToAddress("0x3333333333333333333333333333333333333333") {
		t.Fatal("legacy Router selection changed")
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
