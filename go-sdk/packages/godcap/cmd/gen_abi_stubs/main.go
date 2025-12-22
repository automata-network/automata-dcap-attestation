package main

import (
	_ "embed"
	"os"
	"path/filepath"

	"github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/abigen"
	"github.com/chzyer/logex"
)

func genabi(name string) {
	if err := abigen.GenAbiByForgeOutput("../dcap-portal/out", name, "stubs"); err != nil {
		logex.Fatal(err)
	}
}

func genPccsAbi(name string) {
	onChainPccs := os.Getenv("AUTOMATA_ON_CHAIN_PCCS")
	if onChainPccs == "" {
		onChainPccs = filepath.Join("..", "..", "..", "automata-on-chain-pccs")
	}
	if err := abigen.GenAbiByForgeOutput(filepath.Join(onChainPccs, "out"), name, "stubs"); err != nil {
		logex.Fatal(err)
	}
}

func main() {
	genabi("DcapPortal")
	genabi("VerifiedCounter")
	genabi("DcapLibCallback")
	genabi("IDcapAttestation")
	genPccsAbi("AutomataFmspcTcbDao")
	genPccsAbi("AutomataPcsDao")
	genPccsAbi("AutomataEnclaveIdentityDao")
}
