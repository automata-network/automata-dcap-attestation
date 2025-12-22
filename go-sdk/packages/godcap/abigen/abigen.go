package abigen

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/chzyer/logex"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
)

type GenConfig struct {
	Name    string
	JsonAbi []byte
	Out     string
}

func GenAbi(name string, jsonAbi []byte, out string) error {
	code, err := bind.Bind([]string{name}, []string{string(jsonAbi)}, []string{""}, nil, name, bind.LangGo, nil, nil)
	if err != nil {
		return logex.Trace(err)
	}
	outFp := filepath.Join(out, name)
	if err := os.MkdirAll(outFp, 0755); err != nil {
		return logex.Trace(err)
	}
	target := filepath.Join(outFp, name+".go")

	logex.Infof("generate stub %v: %v", name, target)
	if err := os.WriteFile(target, []byte(code), 0644); err != nil {
		return logex.Trace(err)
	}
	return nil
}

type Abi struct {
	Abi json.RawMessage
}

func GenAbiByForgeOutput(forgeOutPath string, name string, genToPath string) error {
	fp := filepath.Join(forgeOutPath, fmt.Sprintf("%v.sol", name), fmt.Sprintf("%v.json", name))
	abiBytes, err := os.ReadFile(fp)
	if err != nil {
		return logex.Trace(err, fp)
	}
	var abi Abi
	if err := json.Unmarshal(abiBytes, &abi); err != nil {
		return logex.Trace(err)
	}
	if err := GenAbi(name, []byte(abi.Abi), genToPath); err != nil {
		return logex.Trace(err)
	}
	return nil
}
