package attestationv2

import (
	"bytes"
	"context"
	"encoding/json"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/parser"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

// Explicit opt-in: this test signs only with an ephemeral test key and refuses
// non-loopback URLs or non-Anvil nodes. It never uses an operator's wallet.
func TestForkRawV2CallsTransactionsAndEvents(t *testing.T) {
	file := os.Getenv("DCAP_ANVIL_REPORT")
	if file == "" {
		t.Skip("DCAP_ANVIL_REPORT required; not a completed fork test")
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
	if err != nil || u.Scheme != "http" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "::1") || u.User != nil {
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
	address := deployment.Contracts["AutomataDcapAttestationV2"].Address
	client, err := New(address, backend)
	if err != nil {
		t.Fatal(err)
	}
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	account := crypto.PubkeyToAddress(key.PublicKey)
	if err = backend.Client().CallContext(ctx, nil, "anvil_setBalance", account, "0x56bc75e2d63100000"); err != nil {
		t.Fatal(err)
	}
	var rows []map[string]interface{}
	for _, name := range []string{"ata-sgx-v3", "ata-tdx-v4", "v5"} {
		t.Run(name, func(t *testing.T) {
			var fixture struct {
				Quote    string `json:"quote"`
				Expected string `json:"expectedJournal"`
				Eval     uint32 `json:"tcbEvaluationDataNumber"`
			}
			data, err := os.ReadFile(filepath.Join("../../../../evm/forge-test/assets/v2/fixtures", name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			if err = json.Unmarshal(data, &fixture); err != nil {
				t.Fatal(err)
			}
			quote := common.FromHex(fixture.Quote)
			expected, err := parser.ParseOutputV2(common.FromHex(fixture.Expected))
			if err != nil {
				t.Fatal(err)
			}
			header, err := backend.HeaderByNumber(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			expected.Timestamp = header.Time
			wire, err := expected.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			opts := &bind.CallOpts{Context: ctx, From: account}
			actual, err := client.VerifyAndAttestOnChainV2(opts, quote, fixture.Eval, false)
			if err != nil || !bytes.Equal(actual.Output, wire) {
				t.Fatalf("explicit call/parity: %v", err)
			}
			actual, err = client.VerifyAndAttestOnChainV2Default(opts, quote)
			if err != nil || !bytes.Equal(actual.Output, wire) {
				t.Fatalf("default call/parity: %v", err)
			}
			actual, err = client.VerifyAndAttestOnChainV2(opts, quote, fixture.Eval, true)
			if err != nil || !bytes.Equal(actual.Output, wire) {
				t.Fatalf("minimal call/parity: %v", err)
			}
			changed := append([]byte(nil), quote...)
			changed[80] ^= 1
			if _, err = client.VerifyAndAttestOnChainV2(opts, changed, fixture.Eval, false); err == nil {
				t.Fatal("modified quote accepted")
			}
			if _, err = client.VerifyAndAttestOnChainV2(opts, append(append([]byte(nil), quote...), 0), fixture.Eval, false); err == nil {
				t.Fatal("padded quote accepted")
			}
			if _, err = client.VerifyAndAttestOnChainV2(opts, quote, ^uint32(0), false); err == nil {
				t.Fatal("invalid evaluation accepted")
			}
			for _, automatic := range []bool{false, true} {
				auth, err := bind.NewKeyedTransactorWithChainID(key, new(big.Int).SetUint64(info.Environment.ChainID))
				if err != nil {
					t.Fatal(err)
				}
				auth.Context = ctx
				auth.Value = big.NewInt(100000000000000000)
				var tx *types.Transaction
				if automatic {
					// The SDK currently exposes only an explicit raw transaction helper;
					// exercise the default overload through its embedded ABI binding.
					method, methodErr := client.method("verifyAndAttestOnChainV2(bytes)")
					if methodErr != nil {
						t.Fatal(methodErr)
					}
					tx, err = client.contract.Transact(auth, method, quote)
				} else {
					tx, err = client.TransactOnChainV2(auth, quote, fixture.Eval, false)
				}
				if err != nil {
					t.Fatal(err)
				}
				receipt, err := bind.WaitMined(ctx, backend, tx)
				if err != nil {
					t.Fatal(err)
				}
				if receipt.Status != types.ReceiptStatusSuccessful {
					t.Fatal("raw transaction reverted")
				}
				header, err = backend.HeaderByNumber(ctx, receipt.BlockNumber)
				if err != nil {
					t.Fatal(err)
				}
				expected.Timestamp = header.Time
				wire, err = expected.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
				found := 0
				for _, log := range receipt.Logs {
					if log.Address != address {
						continue
					}
					event, err := client.ParseAttestationSubmittedV2(*log)
					if err != nil {
						t.Fatal(err)
					}
					if !event.Success || event.VerifierType != 0 || event.FormatMajorVersion != 2 || event.FormatMinorVersion != 1 || !bytes.Equal(event.Output, wire) {
						t.Fatal("event/output mismatch")
					}
					found++
				}
				if found != 1 {
					t.Fatal("expected one V2 event")
				}
				t.Logf("raw SDK transaction default=%t gas=%d tx=%s", automatic, receipt.GasUsed, tx.Hash())
				rows = append(rows, map[string]interface{}{"fixture": name, "automatic": automatic, "transactionHash": tx.Hash(), "gasUsed": receipt.GasUsed, "calldataBytes": len(tx.Data()), "receipt": receipt, "timestamp": header.Time})
			}
		})
	}
	if file := os.Getenv("DCAP_SDK_GAS_REPORT"); file != "" {
		status := "PASS"
		if t.Failed() {
			status = "FAILED"
		}
		payload, err := json.MarshalIndent(map[string]interface{}{"sdk": "go", "status": status, "scope": "raw explicit/default eth_call, three negatives, signed explicit SDK/default ABI-binding transactions and event parity", "results": rows}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		out, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		defer out.Close()
		if _, err = out.Write(payload); err != nil {
			t.Fatal(err)
		}
	}
}
