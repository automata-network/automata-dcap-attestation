package main

import (
	"fmt"
	"os"

	"github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/registry"
	"github.com/chzyer/flagly"
	"github.com/chzyer/logex"
)

type GoDcap struct {
	Config   *GoDcapConfig   `flagly:"handler"`
	Examples *GoDcapExamples `flagly:"handler"`
}

type GoDcapConfig struct {
	Contract *GoDcapConfigContract `flagly:"handler"`
}

type GoDcapConfigContract struct {
	ChainId uint64 `type:"[0]"`
}

func (g *GoDcapConfigContract) FlaglyHandle() error {
	if g.ChainId == 0 {
		return flagly.ErrShowUsage
	}
	network, err := registry.ByChainID(g.ChainId)
	if err != nil {
		return logex.NewErrorf("chain_id=%v not found", g.ChainId)
	}
	fmt.Println(network.Contracts.Dcap.DcapAttestationFee)
	return nil
}

func main() {
	if err := flagly.RunByArgs(&GoDcap{}, os.Args); err != nil {
		logex.Fatal(err)
	}
}
