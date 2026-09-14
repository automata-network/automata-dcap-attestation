package feev2

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/parser"
	"github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/pccs"
	"github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/registry"
	"github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/zkdcap"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

// Acquires real on-chain collateral using SDK API selection, not fixture collateral.
// Feed the exported inputs into fork_v2_collateral for independent native validation.
func TestForkV2CollateralAcquisition(t *testing.T) {
	file, outDir := os.Getenv("DCAP_ANVIL_REPORT"), os.Getenv("DCAP_COLLATERAL_GO_OUT")
	if file == "" || outDir == "" {
		t.Skip("deployment report and new output directory required; not a completed fork test")
	}
	var deployment forkDeployment
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, &deployment); err != nil {
		t.Fatal(err)
	}
	if deployment.Status != "DEPLOYMENT_AND_COLLATERAL_TRANSACTIONS_PASS" {
		t.Fatal("deployment not ready")
	}
	u, err := url.Parse(deployment.RPC)
	if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.User != nil {
		t.Fatal("local Anvil only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	backend, err := ethclient.DialContext(ctx, deployment.RPC)
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	var info forkNodeInfo
	if err = backend.Client().CallContext(ctx, &info, "anvil_nodeInfo"); err != nil {
		t.Fatal(err)
	}
	requireReviewedFork(t, deployment.Origin, info)
	start, err := backend.BlockNumber(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// V2 reuses the existing PCCS; no global V2 Fee address is registered here.
	network, err := registry.ByChainIDVersion(info.Environment.ChainID, registry.VersionV1_1)
	if err != nil {
		t.Fatal(err)
	}
	ps, err := pccs.NewClient(backend, network)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(outDir, 0700); err != nil {
		t.Fatal(err)
	}
	var rows []map[string]interface{}
	for _, name := range []string{"ata-sgx-v3", "ata-tdx-v4", "v5"} {
		var f struct {
			Quote                   string
			VerificationTimestamp   uint64
			TcbEvaluationDataNumber uint32
		}
		data, err = os.ReadFile(filepath.Join("../../../../evm/forge-test/assets/v2/fixtures", name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(data, &f); err != nil {
			t.Fatal(err)
		}
		quote := common.FromHex(f.Quote)
		q, err := parser.NewQuoteParserSafe(quote)
		if err != nil {
			t.Fatal(err)
		}
		for _, mode := range []string{"explicit", "default"} {
			var eval *uint32
			if mode == "explicit" {
				eval = &f.TcbEvaluationDataNumber
			}
			started := time.Now()
			c, err := zkdcap.NewCollateralV2FromQuoteParser(ctx, q, ps, eval)
			acquisitionMS := float64(time.Since(started).Nanoseconds()) / 1e6
			if err != nil {
				t.Fatalf("%s/%s acquisition: %v", name, mode, err)
			}
			started = time.Now()
			input, err := zkdcap.GenerateInputV2(quote, c, f.VerificationTimestamp)
			encodingUS := float64(time.Since(started).Nanoseconds()) / 1e3
			if err != nil {
				t.Fatalf("%s/%s input: %v", name, mode, err)
			}
			filename := name + "-" + mode + ".bin"
			out, err := os.OpenFile(filepath.Join(outDir, filename), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				t.Fatal(err)
			}
			_, writeErr := out.Write(input)
			closeErr := out.Close()
			if writeErr != nil || closeErr != nil {
				t.Fatalf("write input: %v / %v", writeErr, closeErr)
			}
			rows = append(rows, map[string]interface{}{"fixture": name, "evaluationMode": mode, "inputFile": filename, "inputKeccak256": crypto.Keccak256Hash(input), "acquisitionElapsedMs": acquisitionMS, "encodingElapsedMicros": encodingUS})
			t.Logf("PASS %s/%s PCCS acquisition and ABI generation; native journal verification remains required", name, mode)
		}
	}
	end, err := backend.BlockNumber(ctx)
	if err != nil || end != start {
		t.Fatalf("read-only fork changed: %d -> %d: %v", start, end, err)
	}
	data, err = json.MarshalIndent(map[string]interface{}{"status": "INPUT_GENERATION_PASS", "scope": "SDK PCCS acquisition and ABI generation only; validate journals with Rust runner", "sdk": "go", "origin": info, "blockNumber": start, "results": rows}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(outDir, "report.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
}
