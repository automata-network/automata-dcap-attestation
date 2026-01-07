package godcap

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/parser"
	"github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/pccs"
	"github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/registry"
	"github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/stubs/DcapLibCallback"
	gen "github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/stubs/DcapPortal"
	"github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/stubs/IDcapAttestation"
	"github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/zkdcap"
	"github.com/chzyer/logex"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

const basefeeMultiplier = 2

var (
	ErrValueShouldBeNil        = logex.Define("value in TransactOpts should be nil")
	ErrTransactOptsMissingFrom = logex.Define("TransactOpts missing from")
	ErrInsuccifientFunds       = logex.Define("InsuccifientFunds")
	DcapError                  = map[string]string{
		"0x1356a63b": "AutomataDcapAttestation: BP_Not_Valid()",
		"0x1a72054d": "AutomataDcapAttestation: Insuccifient_Funds()",
		"0xc40a532b": "AutomataDcapAttestation: Withdrawal_Failed()",
	}
)

type DcapPortalOption func(context.Context, *DcapPortal) error

// Connect to the portal with the provided endpoint
func WithEndpoint(endpoint string) DcapPortalOption {
	return func(ctx context.Context, p *DcapPortal) error {
		if p.client != nil {
			return logex.NewErrorf("client already set")
		}

		client, err := ethclient.Dial(endpoint)
		if err != nil {
			return logex.Trace(err)
		}

		return WithClient(client)(ctx, p)
	}
}

// Connect to the portal with the provided client
func WithClient(client *ethclient.Client) DcapPortalOption {
	return func(ctx context.Context, p *DcapPortal) error {
		if p.client != nil {
			return logex.NewErrorf("client already set")
		}

		chainId, err := client.ChainID(ctx)
		if err != nil {
			return logex.Trace(err)
		}

		p.chainID = chainId.Int64()
		p.client = client
		if p.network == nil {
			network, err := registry.ByChainID(uint64(p.chainID))
			if err != nil {
				return logex.NewErrorf("network config not found for chain id %v", p.chainID)
			}
			WithNetwork(network)(ctx, p)
		}
		return nil
	}
}

// WithNetwork sets the network configuration
func WithNetwork(network *registry.Network) DcapPortalOption {
	return func(ctx context.Context, p *DcapPortal) error {
		if p.network != nil {
			return logex.NewErrorf("network already set")
		}

		p.network = network
		return nil
	}
}


func WithPrivateKey(key string) DcapPortalOption {
	return func(ctx context.Context, p *DcapPortal) error {
		privateKey, err := crypto.HexToECDSA(key)
		if err != nil {
			return logex.Trace(err)
		}
		p.privateKey = privateKey
		return nil
	}
}

// Enable zero-knowledge proof functionality
// cfg can be nil
func WithZkProof(cfg *zkdcap.ZkProofConfig) DcapPortalOption {
	return func(ctx context.Context, p *DcapPortal) error {
		if cfg == nil {
			cfg = new(zkdcap.ZkProofConfig)
		}
		p.zkConfig = cfg
		return nil
	}
}

// DcapPortal represents the main interface for interacting with DCAP attestation
type DcapPortal struct {
	client     *ethclient.Client
	chainID    int64
	zkConfig   *zkdcap.ZkProofConfig
	network    *registry.Network
	eip1559    bool // Whether to use EIP-1559 transactions
	privateKey *ecdsa.PrivateKey

	Stub    *gen.DcapPortal
	abi     abi.ABI
	dcapAbi abi.ABI
	pccs    *pccs.Client

	zkProof *zkdcap.ZkProofClient
}

// NewDcapPortal creates a new instance of DcapPortal with the provided options.
// It will connect to AutomataTestnet(https://explorer-testnet.ata.network) by default
func NewDcapPortal(ctx context.Context, options ...DcapPortalOption) (*DcapPortal, error) {
	var portal DcapPortal
	for _, option := range options {
		if err := option(ctx, &portal); err != nil {
			return nil, logex.Trace(err)
		}
	}
	if portal.network == nil {
		network, err := registry.Default()
		if err != nil {
			return nil, logex.Trace(err, "failed to get default network")
		}
		if err := WithNetwork(network)(ctx, &portal); err != nil {
			return nil, logex.Trace(err)
		}
	}

	// try to connect to the default endpoint if client is not set
	if portal.client == nil {
		endpoint := portal.network.DefaultRpcUrl()
		if endpoint != "" {
			if err := WithEndpoint(endpoint)(ctx, &portal); err != nil {
				return nil, logex.Trace(err, "defaultEndpoint", endpoint)
			}
		}
	}
	if portal.client == nil {
		return nil, logex.NewError("client is not set")
	}

	// Check if DcapPortal is available for this network
	portalAddr := portal.network.Contracts.Dcap.DcapPortal
	if portalAddr == (common.Address{}) {
		return nil, logex.NewErrorf("DcapPortal not available for network %s", portal.network.Key)
	}

	stub, err := gen.NewDcapPortal(portalAddr, portal.client)
	if err != nil {
		return nil, logex.Trace(err)
	}
	portal.Stub = stub

	portalAbi, err := abi.JSON(strings.NewReader(gen.DcapPortalABI))
	if err != nil {
		return nil, logex.Trace(err)
	}
	portal.abi = portalAbi

	libAbi, err := abi.JSON(strings.NewReader(DcapLibCallback.DcapLibCallbackABI))
	if err != nil {
		return nil, logex.Trace(err)
	}
	for name, err := range libAbi.Errors {
		portalAbi.Errors[name] = err
	}

	dcapAbi, err := abi.JSON(strings.NewReader(IDcapAttestation.IDcapAttestationABI))
	if err != nil {
		return nil, logex.Trace(err)
	}
	portal.dcapAbi = dcapAbi

	// Default to EIP-1559 transactions
	portal.eip1559 = true

	pccsClient, err := pccs.NewClient(portal.client, portal.network)
	if err != nil {
		return nil, logex.Trace(err)
	}
	portal.pccs = pccsClient

	zkProofClient, err := zkdcap.NewZkProofClient(portal.zkConfig, pccsClient)
	if err != nil {
		return nil, logex.Trace(err)
	}
	portal.zkProof = zkProofClient

	return &portal, nil
}

// Pccs returns the PCCS server instance associated with the DcapPortal.
func (d *DcapPortal) Pccs() *pccs.Client {
	return d.pccs
}

// BuildTransactOpts builds transaction options using the provided private key.
// Returns error if key transactor creation or options normalization fails.
func (p *DcapPortal) BuildTransactOpts(ctx context.Context) (*bind.TransactOpts, error) {
	if p.privateKey == nil {
		return nil, logex.NewError("private key is not set(WithPrivateKey)")
	}

	opts, err := bind.NewKeyedTransactorWithChainID(p.privateKey, big.NewInt(int64(p.network.ChainID)))
	if err != nil {
		return nil, logex.Trace(err)
	}
	opts.Context = ctx
	return p.normalizeOpts(opts)
}

// WaitTx waits for the transaction receipt and returns it through a channel.
func (p *DcapPortal) WaitTx(ctx context.Context, tx *types.Transaction) <-chan *types.Receipt {
	result := make(chan *types.Receipt)
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				receipt, err := p.client.TransactionReceipt(ctx, tx.Hash())
				if err != nil {
					logex.Infof("waiting tx receipt for %v: %v", tx.Hash(), err)
					continue
				}

				logex.Infof("tx receipt %v comfirmed on %v", tx.Hash(), receipt.BlockNumber)
				if explorer := p.network.DefaultExplorer(); explorer != "" {
					logex.Infof("explorer: %v/tx/%v", explorer, tx.Hash())
				}
				result <- receipt
				return
			}
		}
	}()

	return result
}

// VerifyOnChain submits quote for on-chain verification with callback.
// Returns transaction hash and error if submission fails.
func (p *DcapPortal) VerifyAndAttestOnChain(opts *bind.TransactOpts, rawQuote []byte, callback *Callback) (*types.Transaction, error) {
	var err error
	if opts == nil {
		opts, err = p.BuildTransactOpts(context.Background())
		if err != nil {
			return nil, logex.Trace(err)
		}
	}

	params, err := callback.Abi()
	if err != nil {
		return nil, logex.Trace(err)
	}
	opts, err = p.normalizeOpts(opts)
	if err != nil {
		return nil, logex.Trace(err)
	}
	feeBase, err := p.EstimateBaseFeeVerifyOnChain(opts.Context, rawQuote)
	if err != nil {
		return nil, logex.Trace(p.decodeErr(err, callback))
	}
	opts.Value = new(big.Int).Add(p.attestationFee(opts, feeBase), params.Value)

	newTx, err := p.Stub.VerifyAndAttestOnChain(opts, rawQuote, params)
	if err != nil {
		return nil, logex.Trace(p.decodeErr(err, callback))
	}
	return newTx, nil
}

// GenerateZkProof generates zero-knowledge proof for the given quote.
// Returns error if zkproof client is not initialized or proof generation fails.
//
// Note: EnableZkProof() should be called before using this function.
func (p *DcapPortal) GenerateZkProof(ctx context.Context, ty zkdcap.ZkType, quote []byte) (*zkdcap.ZkProof, error) {
	if p.zkProof == nil {
		return nil, logex.NewErrorf("DcapPortal should call EnableZkProof() frist")
	}
	parser := parser.NewQuoteParser(quote)
	collateral, err := zkdcap.NewCollateralFromQuoteParser(ctx, parser, p.pccs)
	if err != nil {
		return nil, logex.Trace(err)
	}
	return p.zkProof.ProveQuote(ctx, ty, quote, collateral)
}

// VerifyAndAttestWithZKProof verifies and attests the ZK proof on chain.
// Returns transaction hash and error if verification fails.
func (p *DcapPortal) VerifyAndAttestWithZKProof(opts *bind.TransactOpts, zkProof *zkdcap.ZkProof, callback *Callback) (*types.Transaction, error) {
	var err error
	if opts == nil {
		opts, err = p.BuildTransactOpts(context.Background())
		if err != nil {
			return nil, logex.Trace(err)
		}
	}

	params, err := callback.Abi()
	if err != nil {
		return nil, logex.Trace(err)
	}
	opts, err = p.normalizeOpts(opts)
	if err != nil {
		return nil, logex.Trace(err)
	}
	feeBase, err := p.EstimateBaseFeeVerifyAndAttestWithZKProof(opts.Context, zkProof)
	if err != nil {
		return nil, logex.Trace(p.decodeErr(err, callback))
	}
	opts.Value = new(big.Int).Add(p.attestationFee(opts, feeBase), params.Value)

	newTx, err := p.Stub.VerifyAndAttestWithZKProof(opts, zkProof.Output, uint8(zkProof.Type), zkProof.Proof, params)
	if err != nil {
		return nil, logex.Trace(p.decodeErr(err, callback))
	}
	return newTx, nil
}

// EstimateFeeBaseVerifyOnChain estimates the base fee for quote verification.
// The actual fee will be base fee multiplied by gas price.
func (p *DcapPortal) EstimateBaseFeeVerifyOnChain(ctx context.Context, rawQuote []byte) (*big.Int, error) {
	result, err := p.callContract(ctx, &p.abi, "estimateBaseFeeVerifyOnChain", rawQuote)
	if err != nil {
		return nil, logex.Trace(err)
	}
	return result[0].(*big.Int), nil
}

// EstimateFeeBaseVerifyAndAttestWithZKProof estimates the base fee for ZK proof verification and attestation.
// The actual fee will be base fee multiplied by gas price.
func (p *DcapPortal) EstimateBaseFeeVerifyAndAttestWithZKProof(ctx context.Context, zkProof *zkdcap.ZkProof) (*big.Int, error) {
	result, err := p.callContract(ctx, &p.abi, "estimateBaseFeeVerifyAndAttestWithZKProof", zkProof.Output, uint8(zkProof.Type), zkProof.Proof)
	if err != nil {
		return nil, logex.Trace(err)
	}
	return result[0].(*big.Int), nil
}

// CheckQuote verifies if a quote is valid by doing a simulated call.
// Returns true if quote is valid, false otherwise.
func (p *DcapPortal) CheckQuote(ctx context.Context, quote []byte) (bool, error) {
	args, err := p.callContract(ctx, &p.dcapAbi, "verifyAndAttestOnChain", quote)
	if err != nil {
		return false, logex.Trace(err)
	}
	return args[0].(bool), nil
}

// CheckZkProof verifies if a ZK proof is valid by doing a simulated call.
// Returns true if proof is valid, false otherwise.
func (p *DcapPortal) CheckZkProof(ctx context.Context, proof *zkdcap.ZkProof) (bool, error) {
	args, err := p.callContract(ctx, &p.dcapAbi, "verifyAndAttestWithZKProof", proof.Output, proof.Type, proof.Proof)
	if err != nil {
		return false, logex.Trace(err)
	}
	return args[0].(bool), nil
}

// EstimateAttestationFee estimates the attestation fee for a transaction.
func (p *DcapPortal) EstimateAttestationFee(tx *types.Transaction, callback *Callback) *big.Int {
	return new(big.Int).Sub(tx.Value(), callback.Value())
}

// CalculateAttestationFee calculates the actual attestation fee based on the transaction receipt.
func (p *DcapPortal) CalculateAttestationFee(tx *types.Transaction, callback *Callback, receipt *types.Receipt) *big.Int {
	estimateFee := p.EstimateAttestationFee(tx, callback)
	feeBase := new(big.Int).Div(estimateFee, tx.GasFeeCap())
	fee := new(big.Int).Mul(feeBase, receipt.EffectiveGasPrice)
	return fee
}

// PrintAttestationFee prints the attestation fee details for a transaction.
func (p *DcapPortal) PrintAttestationFee(tx *types.Transaction, callback *Callback, receipt *types.Receipt) {
	fmt.Println("Tx GasPrice:", tx.GasPrice())
	fmt.Println("Callback Value:", callback.Value())
	fmt.Println("Receipt EffectiveGasPrice:", receipt.EffectiveGasPrice)
	estimateFee := p.EstimateAttestationFee(tx, callback)
	fmt.Println("EstimateAttestationFee:", estimateFee)
	feeBase := new(big.Int).Div(estimateFee, tx.GasFeeCap())
	fmt.Println("EstimateFeeBase(over actual value):", feeBase)
	fee := new(big.Int).Mul(feeBase, receipt.EffectiveGasPrice)
	fmt.Println("Estimate EffectiveAttestationFee(over actual value):", fee)
	fmt.Println("Total Sent:", tx.Value())
	refund := new(big.Int).Sub(tx.Value(), callback.Value())
	refund = refund.Sub(refund, fee)
	fmt.Println("Estimate Refund(under actual value):", refund)
}

// Client returns the Ethereum client associated with the DcapPortal.
func (p *DcapPortal) Client() *ethclient.Client {
	return p.client
}

// callContract performs a contract call with the specified method and arguments
// Returns the result of the call or an error if the call fails
func (p *DcapPortal) callContract(ctx context.Context, abi *abi.ABI, method string, args ...interface{}) ([]interface{}, error) {
	var from common.Address
	if p.privateKey != nil {
		from = crypto.PubkeyToAddress(p.privateKey.PublicKey)
	}
	value, err := p.client.BalanceAt(ctx, from, nil)
	if err != nil {
		return nil, logex.Trace(err)
	}

	calldata, err := abi.Pack(method, args...)
	if err != nil {
		return nil, logex.Trace(err)
	}
	var to common.Address
	if abi == &p.abi {
		to = p.network.Contracts.Dcap.DcapPortal
	} else if abi == &p.dcapAbi {
		to = p.network.Contracts.Dcap.DcapAttestationFee
	} else {
		return nil, logex.NewError("unknown abi")
	}
	msg := ethereum.CallMsg{
		From:  from,
		To:    &to,
		Value: value,
		Data:  calldata,
	}
	data, err := p.client.CallContract(ctx, msg, nil)
	if err != nil {
		return nil, logex.Trace(p.decodeErr(err, nil))
	}
	result, err := abi.Unpack(method, data)
	if err != nil {
		return nil, logex.Trace(err)
	}
	return result, nil
}

// decodeErrData decodes error data from a contract call
// Returns a formatted error message
func (p *DcapPortal) decodeErrData(abi *abi.ABI, msg string, dataBytes []byte, callback *Callback) error {
	sig := dataBytes
	if len(sig) > 4 {
		sig = sig[:4]
	}
	for name, er := range abi.Errors {
		if bytes.Equal(er.ID[:4], sig) {
			args, _ := er.Inputs.Unpack(dataBytes[len(sig):])
			for idx := range args {
				if b, ok := args[idx].([]byte); ok {
					args[idx] = hexutil.Bytes(b)
				}
			}
			if name == "CALLBACK_FAILED" {
				if callback != nil {
					return logex.Trace(p.decodeErrData(&callback.abi, msg, args[0].(hexutil.Bytes), nil), "callbackFailed")
				}
				return logex.Trace(p.decodeErrData(abi, msg, args[0].(hexutil.Bytes), nil), "callbackFailed")
			}
			return logex.NewErrorf("%v: %v(%v)", msg, name, args)
		}
	}
	return logex.NewErrorf("%v: %v", msg, hexutil.Bytes(dataBytes))
}

// decodeErr decodes a JSON error from a contract call
// Returns a formatted error message
func (p *DcapPortal) decodeErr(err error, callback *Callback) error {
	if err == nil {
		return nil
	}

	jerr, ok := err.(JsonError)
	if !ok {
		return err
	}

	data, ok := jerr.ErrorData().(string)
	if !ok {
		return err
	}
	if sig, ok := DcapError[data]; ok {
		return fmt.Errorf("%v: %v", jerr.Error(), sig)
	}
	dataBytes, er := hex.DecodeString(strings.TrimPrefix(data, "0x"))
	if er == nil {
		return p.decodeErrData(&p.abi, jerr.Error(), dataBytes, callback)
	}
	return logex.NewErrorf("%v: %v", jerr.Error(), data)

}

// attestationFee calculates the attestation fee based on the transaction options and fee base
func (p *DcapPortal) attestationFee(opts *bind.TransactOpts, feeBase *big.Int) *big.Int {
	if p.eip1559 {
		return new(big.Int).Mul(opts.GasFeeCap, feeBase)
	} else {
		return new(big.Int).Mul(opts.GasPrice, feeBase)
	}
}

// normalizeOpts normalizes the transaction options by setting default values
// Handles both EIP1559 and legacy transaction types
func (p *DcapPortal) normalizeOpts(optsRef *bind.TransactOpts) (*bind.TransactOpts, error) {
	var opts bind.TransactOpts
	if optsRef != nil {
		opts = *optsRef
	}
	if opts.Context == nil {
		opts.Context = context.Background()
	}
	if opts.Value != nil {
		return nil, ErrValueShouldBeNil.Trace()
	}

	var head *types.Header
	var err error

	if p.eip1559 && opts.GasFeeCap == nil {
		head, err = p.client.HeaderByNumber(opts.Context, nil)
		if err != nil {
			return nil, logex.Trace(err)
		}
		if head.BaseFee == nil && p.eip1559 {
			p.eip1559 = false
		}
	}

	if p.eip1559 {
		if opts.GasTipCap == nil {
			tip, err := p.client.SuggestGasTipCap(opts.Context)
			if err != nil {
				return nil, logex.Trace(err)
			}
			opts.GasTipCap = tip
		}
		if opts.GasFeeCap == nil {
			opts.GasFeeCap = new(big.Int).Add(
				opts.GasTipCap,
				new(big.Int).Mul(head.BaseFee, big.NewInt(basefeeMultiplier)),
			)
		}
	} else {
		if opts.GasPrice == nil {
			price, err := p.client.SuggestGasPrice(opts.Context)
			if err != nil {
				return nil, logex.Trace(err)
			}
			opts.GasPrice = price
		}
	}

	return &opts, nil
}

// JsonError represents a JSON error with code and data
type JsonError interface {
	Error() string
	ErrorCode() int
	ErrorData() interface{}
}
