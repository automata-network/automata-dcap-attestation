package godcap

import (
	"context"
	"encoding/hex"
	"math/big"
	"os"
	"testing"

	"github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/mock"
	"github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/registry"
	"github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/stubs/VerifiedCounter"
	"github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/zkdcap"
	"github.com/chzyer/logex"
	"github.com/chzyer/test"
	"github.com/ethereum/go-ethereum/common"
)

var verifiedCounterAddr = common.HexToAddress("0xa39aE3295e8142A0680131ff662a4AB2ec721dFD")

func TestDcapPortalOnChain(t *testing.T) {
	defer test.New(t)

	ctx := context.Background()
	privateKey := os.Getenv("PRIVATE_KEY")
	if privateKey == "" {
		logex.Info("skip testing DcapPortal because env var PRIVATE_KEY is empty")
		return
	}

	network := registry.AutomataTestnet()
	portal, err := NewDcapPortal(ctx, WithPrivateKey(privateKey), WithEndpoint(network.DefaultRpcUrl()))
	test.Nil(err)

	counter, err := VerifiedCounter.NewVerifiedCounterCaller(verifiedCounterAddr, portal.Client())
	test.Nil(err)

	originCounter, err := counter.Number(nil)
	test.Nil(err)

	// deposit 10 wei to increase the counter, check the logic from ../dcap-portal/src/examples/VerifiedCounter.sol
	callback := NewCallbackFromAbiJSON(VerifiedCounter.VerifiedCounterABI).
		WithParams("deposit").
		WithTo(verifiedCounterAddr).
		WithValue(big.NewInt(10))

	tx, err := portal.VerifyAndAttestOnChain(nil, mock.Quotes[0], callback)
	test.Nil(err)

	receipt := <-portal.WaitTx(ctx, tx)

	portal.PrintAttestationFee(tx, callback, receipt)

	newCounter, err := counter.Number(nil)
	if err != nil {
		t.Fatal(err)
	}

	if new(big.Int).Sub(newCounter, originCounter).Cmp(big.NewInt(10)) != 0 {
		t.Fatalf("counter mismatch: origin=%v, new=%v", originCounter, newCounter)
	}
}

func TestSp1(t *testing.T) {
	privateKey := os.Getenv("NETWORK_PRIVATE_KEY")
	if privateKey == "" {
		logex.Info("skip testing sp1 because env var NETWORK_PRIVATE_KEY is empty")
		return
	}

	ctx := context.Background()
	network := registry.AutomataTestnet()
	portal, err := NewDcapPortal(ctx, WithEndpoint(network.DefaultRpcUrl()), WithZkProof(nil))
	if err != nil {
		t.Fatal(err)
	}
	zkproof, err := portal.GenerateZkProof(ctx, zkdcap.ZkTypeSuccinct, mock.Quotes[1])
	if err != nil {
		logex.Error(err)
		t.Fatal(err)
	}
	succ, err := portal.CheckZkProof(ctx, zkproof)
	if err != nil {
		logex.Error(err)
		t.Fatal(err)
	}
	if !succ {
		t.Fatal("verify zkproof failed")
	}
}

func TestRisc0(t *testing.T) {
	privateKey := os.Getenv("BONSAI_API_KEY")
	if privateKey == "" {
		logex.Info("skip testing risc0 because env var BONSAI_API_KEY is empty")
		return
	}

	ctx := context.Background()
	network := registry.AutomataTestnet()
	portal, err := NewDcapPortal(ctx, WithEndpoint(network.DefaultRpcUrl()), WithZkProof(nil))
	if err != nil {
		t.Fatal(err)
	}
	zkproof, err := portal.GenerateZkProof(ctx, zkdcap.ZkTypeRiscZero, mock.Quotes[1])
	if err != nil {
		logex.Error(err)
		t.Fatal(err)
	}
	succ, err := portal.CheckZkProof(ctx, zkproof)
	if err != nil {
		logex.Error(err)
		t.Fatal(err)
	}
	if !succ {
		t.Fatal("verify zkproof failed")
	}
}

// we use a mock attestation contract to test the attestation fee
func TestDcapPortalWithFee(t *testing.T) {
	defer test.New(t)
	ctx := context.Background()

	privateKey := os.Getenv("PRIVATE_KEY")
	if privateKey == "" {
		logex.Info("skip testing DcapPortal because env var PRIVATE_KEY is empty")
		return
	}

	// Copy the network and override addresses for testing
	network := *registry.AutomataTestnet()
	network.Contracts.Dcap.DcapAttestationFee = common.HexToAddress("0xA0c3a7C811e3B6b7D7a381b3aD29A7FCF9048DFf")
	network.Contracts.Dcap.DcapPortal = common.HexToAddress("0x1aFedD4123494f83ADc166A4Fd6Da96321c88c41")

	mockVerifiedCounterAddr := common.HexToAddress("0x5BE14673A6d40C711F082D6f7e4796E2fC57d7b2")
	callback := NewCallbackFromAbiJSON(VerifiedCounter.VerifiedCounterABI).
		WithParams("deposit").
		WithTo(mockVerifiedCounterAddr).
		WithValue(big.NewInt(10))

	portal, err := NewDcapPortal(ctx, WithNetwork(&network), WithPrivateKey(privateKey))
	test.Nil(err)

	succ, err := portal.CheckQuote(ctx, mock.Quotes[0])
	test.Nil(err)
	test.True(succ)

	opt, err := portal.BuildTransactOpts(ctx)
	test.Nil(err)
	opt.NoSend = true

	_, err = portal.VerifyAndAttestOnChain(opt, mock.Quotes[0], callback)
	test.Nil(err)
}

func TestDcapPortalZkProof(t *testing.T) {
	defer test.New(t)
	ctx := context.Background()
	output, _ := hex.DecodeString("02550004810000000790c06f000000040102000000000000000000000000009790d89a10210ec6968a773cee2ca05b5aa97309f36727a968527be4606fc19e6f73acce350946c9d46a9bf7a63f843000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000080e702060000000000f2dd2696f69b950645832bdc095ffd11247eeff687eeacdb57a58d2ddb9a9f94fea40c961e19460c00ffa31420ecbc180000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000998204508d58dcbfebe5e11c48669f7a921ac2da744dfb7d014ecdff2acdff1c9f665fdad52aadacf296a1df9909eb2383d100224f1716aeb431f7cb3cf028197dbd872487f27b0f6329ab17647dc9953c7014109818634f879e6550bc60f93eecfc42ff4d49278bfdbb0c77e570f4490cff10a2ee1ac11fbd2c2b49fa6cfa3cf1a1cb755c72522dd8a689e9d47906a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000278e753482976c8a7351fe2113609c7350d491cdae3d449eefc202fa41b2ad6840239cc2ba084c2d594b4e6dabeae0fcbf71c96daf0d0c9ecf0e9810c04579000000000067e0d9ecd13640a487f29bfe9f18245f06947322bc225541c05b27da6c65a17ff486b948a7fa01fc7a25a72b367cd8bd6aed0bb37108920a3292f557465b91fac3a68eb10fa74a3f32c80b978c8ad671395dabf24283eef9091bc3919fd39b9915a87f1adf3061c165c0191e2658256a2855cac9267f179aafb1990c9e918d6452816adf9953f245d005b9d7d8e36a842a60b51e5cf85b2c2072ae397c178535c9985b77b9e8dcda64e161c988ef2a42c283b203e534bcd2b23fbdbd5785747d8e4ed2f8")
	seal, _ := hex.DecodeString("c101b42b07e881b762f76783c1b2b109add91d4ed52208b8ea345fddbe9b8d8e94e4995f28f8de92e3e082e6cbbcfa849fb22484c3edbbafec9352710d4bbd313ea92c1b17ee1990a815e1298bc9176e54b077968a31a965022c80b63331397c766a020c0702b424b623926c36422b3d0fffa79b75d6dee838809b9f3647a74d5bfdeb4602da6926ff75b603c4dc75a5ced9bed7cea5872b06e1238b509918d05a3bdb8c087870732718ae8d220dc14add6f37ae4829f7bee6006524faa00e9434ebc74303ce9fd5e3c43f8e11895e8f612f8a0fbfed0263b9251b3377208b6c058c84b319f81b0168fc26c243c04b6d00ffb9110f7b4746c5bb776a9e2080fafa6ae219")
	zkproof := &zkdcap.ZkProof{
		Type:   zkdcap.ZkTypeRiscZero,
		Output: output,
		Proof:  seal,
	}
	portal, err := NewDcapPortal(ctx, WithNetwork(registry.AutomataTestnet()))
	test.Nil(err)

	succ, err := portal.CheckZkProof(ctx, zkproof)
	test.Nil(err)
	if !succ {
		t.Fatal("verify zkproof failed")
	}
}
