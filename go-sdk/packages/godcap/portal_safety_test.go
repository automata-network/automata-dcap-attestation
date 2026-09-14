package godcap

import (
	"context"
	"testing"

	"github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/mock"
	"github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/zkdcap"
)

func TestGenerateZkProofRejectsMalformedQuoteWithoutNetwork(t *testing.T) {
	portal := &DcapPortal{zkProof: &zkdcap.ZkProofClient{}}
	for _, quote := range [][]byte{nil, {3}, make([]byte, 56), mock.Quotes[0][:1013]} {
		if _, err := portal.GenerateZkProof(context.Background(), zkdcap.ZkTypeRiscZero, quote); err == nil {
			t.Fatal("malformed quote accepted")
		}
	}
}
