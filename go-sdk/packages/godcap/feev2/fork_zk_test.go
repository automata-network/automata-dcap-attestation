package feev2

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

// Opt-in real EVM proof only. No mock universal verifier or production wallet.
func TestForkRealZKV2SDK(t *testing.T) {
	deploymentFile, proofFile := os.Getenv("DCAP_ANVIL_REPORT"), os.Getenv("DCAP_EVM_PROOF")
	if deploymentFile == "" || proofFile == "" {
		t.Skip("local deployment and real EVM proof required; not a proof success")
	}
	read := func(file string, target interface{}) {
		t.Helper()
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(data, target); err != nil {
			t.Fatal(err)
		}
	}
	var deployment forkDeployment
	var payload struct {
		Backend           uint8       `json:"backend"`
		ProgramID         common.Hash `json:"programId"`
		Journal           string      `json:"journal"`
		Proof             string      `json:"proof"`
		LocalVerification string      `json:"localVerification"`
	}
	read(deploymentFile, &deployment)
	read(proofFile, &payload)
	if deployment.Status != "DEPLOYMENT_AND_COLLATERAL_TRANSACTIONS_PASS" || payload.LocalVerification != "PASS" || (payload.Backend != 1 && payload.Backend != 2) {
		t.Fatal("deployment/real production-backend proof not ready")
	}
	endpoint, err := url.Parse(deployment.RPC)
	if err != nil || endpoint.Scheme != "http" || (endpoint.Hostname() != "127.0.0.1" && endpoint.Hostname() != "::1") || endpoint.User != nil {
		t.Fatal("loopback Anvil only")
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
	address := deployment.Contracts["AutomataDcapAttestationFeeV2"].Address
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
	if err = backend.Client().CallContext(ctx, nil, "anvil_impersonateAccount", deployment.Owner); err != nil {
		t.Fatal(err)
	}
	defer backend.Client().CallContext(context.Background(), nil, "anvil_stopImpersonatingAccount", deployment.Owner)
	adminABI, err := abi.JSON(strings.NewReader(`[{"type":"function","name":"setZkV2Paused","stateMutability":"nonpayable","inputs":[{"name":"paused","type":"bool"}],"outputs":[]},{"type":"function","name":"zkV2Paused","stateMutability":"view","inputs":[],"outputs":[{"name":"paused","type":"bool"}]}]`))
	if err != nil {
		t.Fatal(err)
	}
	admin := bind.NewBoundContract(address, adminABI, backend, backend, backend)
	var initial []interface{}
	if err = admin.Call(&bind.CallOpts{Context: ctx}, &initial, "zkV2Paused"); err != nil {
		t.Fatal(err)
	}
	originalPause := initial[0].(bool)
	setPause := func(pauseCtx context.Context, paused bool) error {
		data, err := adminABI.Pack("setZkV2Paused", paused)
		if err != nil {
			return err
		}
		var hash common.Hash
		if err = backend.Client().CallContext(pauseCtx, &hash, "eth_sendTransaction", map[string]interface{}{"from": deployment.Owner, "to": address, "data": "0x" + common.Bytes2Hex(data), "gas": "0x186a0"}); err != nil {
			return err
		}
		for i := 0; i < 120; i++ {
			receipt, err := backend.TransactionReceipt(pauseCtx, hash)
			if err == nil {
				if receipt.Status != 1 {
					return fmt.Errorf("pause transaction %s reverted", hash)
				}
				return nil
			}
			time.Sleep(100 * time.Millisecond)
		}
		return context.DeadlineExceeded
	}
	journal, proof := common.FromHex(payload.Journal), common.FromHex(payload.Proof)
	id := [32]byte(payload.ProgramID)
	opts := &bind.CallOpts{Context: ctx, From: account}
	// The fixtures currently proven use evaluation 20. Do not guess other inputs.
	const eval uint32 = 20
	if originalPause {
		if _, err = client.VerifyAndAttestWithZKProofV2(opts, journal, payload.Backend, proof, &id, eval); err == nil {
			t.Fatal("paused V2 accepted")
		}
	}
	if err = setPause(ctx, false); err != nil {
		t.Fatal(err)
	}
	restored := false
	defer func() {
		if restored {
			return
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		if err := setPause(cleanupCtx, originalPause); err != nil {
			t.Errorf("restore pause: %v", err)
		}
	}()
	for _, selectedID := range []*[32]byte{&id, nil} {
		got, err := client.VerifyAndAttestWithZKProofV2(opts, journal, payload.Backend, proof, selectedID, eval)
		if err != nil || !bytes.Equal(got, journal) {
			t.Fatalf("explicit proof SDK parity: %v", err)
		}
	}
	got, err := client.VerifyAndAttestWithZKProofV2Default(opts, journal, payload.Backend, proof)
	if err != nil || !bytes.Equal(got, journal) {
		t.Fatalf("default proof SDK parity: %v", err)
	}
	if len(proof) < 5 || len(journal) < 26 {
		t.Fatal("invalid real-proof framing")
	}
	changedProof := append([]byte(nil), proof...)
	changedProof[len(changedProof)-1] ^= 1
	changedJournal := append([]byte(nil), journal...)
	changedJournal[25] ^= 1
	wrongID := id
	wrongID[31] ^= 1
	for _, negative := range []struct {
		journal, proof []byte
		id             [32]byte
	}{{journal, changedProof, id}, {changedJournal, proof, id}, {journal, proof, wrongID}} {
		if _, err = client.VerifyAndAttestWithZKProofV2(opts, negative.journal, payload.Backend, negative.proof, &negative.id, eval); err == nil {
			t.Fatal("proof/journal/ID negative accepted")
		}
	}
	var rows []map[string]interface{}
	for _, automatic := range []bool{false, true} {
		auth, err := bind.NewKeyedTransactorWithChainID(key, new(big.Int).SetUint64(info.Environment.ChainID))
		if err != nil {
			t.Fatal(err)
		}
		auth.Context = ctx
		auth.Value = big.NewInt(100000000000000000)
		signature := "verifyAndAttestWithZKProofV2(bytes,uint8,bytes,bytes32,uint32)"
		args := []interface{}{journal, payload.Backend, proof, id, eval}
		if automatic {
			signature = "verifyAndAttestWithZKProofV2(bytes,uint8,bytes)"
			args = args[:3]
		}
		method, err := client.method(signature)
		if err != nil {
			t.Fatal(err)
		}
		// No named ZK transact helper exists yet; this exercises SDK ABI bindings.
		tx, err := client.contract.Transact(auth, method, args...)
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := bind.WaitMined(ctx, backend, tx)
		if err != nil {
			t.Fatal(err)
		}
		if receipt.Status != types.ReceiptStatusSuccessful {
			t.Fatal("real ZK transaction reverted")
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
			if !event.Success || event.VerifierType != payload.Backend || !bytes.Equal(event.Output, journal) {
				t.Fatal("ZK event mismatch")
			}
			found++
		}
		if found != 1 {
			t.Fatal("expected one ZK V2 event")
		}
		rows = append(rows, map[string]interface{}{"backend": payload.Backend, "automatic": automatic, "transactionHash": tx.Hash(), "gasUsed": receipt.GasUsed, "calldataBytes": len(tx.Data()), "receipt": receipt})
		t.Logf("real ZK default=%t gas=%d tx=%s", automatic, receipt.GasUsed, tx.Hash())
	}
	if err = setPause(ctx, originalPause); err != nil {
		t.Fatal(err)
	}
	var finalPause []interface{}
	if err = admin.Call(&bind.CallOpts{Context: ctx}, &finalPause, "zkV2Paused"); err != nil {
		t.Fatal(err)
	}
	if finalPause[0].(bool) != originalPause {
		t.Fatal("pause restoration mismatch")
	}
	restored = true
	if file := os.Getenv("DCAP_ZK_SDK_REPORT"); file != "" {
		data, err := json.MarshalIndent(map[string]interface{}{"sdk": "go", "status": "PASS", "scope": "real ZK calls, ABI-binding signed transactions/events, paused and three tampering/ID negatives", "results": rows}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		out, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		defer out.Close()
		if _, err = out.Write(data); err != nil {
			t.Fatal(err)
		}
	}
}
