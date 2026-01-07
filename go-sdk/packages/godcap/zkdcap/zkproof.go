package zkdcap

import (
	"context"
	"encoding/binary"

	"github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/bonsai"
	"github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/pccs"
	"github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/sp1"
	"github.com/chzyer/logex"
)

// ZkType represents the type of zero-knowledge proof
type ZkType uint8

var (
	// ZkTypeRiscZero represents the Risc Zero type
	ZkTypeRiscZero = ZkType(1)
	// ZkTypeSuccinct represents the Succinct type
	ZkTypeSuccinct = ZkType(2)
)

// ZkProof holds the proof and output data for a zero-knowledge proof
type ZkProof struct {
	Type   ZkType
	Output []byte
	Proof  []byte
}

// ZkProofConfig holds the configuration for the ZkProofClient
type ZkProofConfig struct {
	Bonsai *bonsai.Config `json:"bonsai"`
	Sp1    *sp1.Config    `json:"sp1"`
}

// ZkProofClient is a client for generating zero-knowledge proofs
type ZkProofClient struct {
	Bonsai *bonsai.Client
	Sp1    *sp1.Client
	ps     *pccs.Client
}

// NewZkProofClient creates a new ZkProofClient with the given configuration and server
func NewZkProofClient(cfg *ZkProofConfig, ps *pccs.Client) (*ZkProofClient, error) {
	if cfg == nil {
		cfg = new(ZkProofConfig)
	}
	if cfg.Bonsai == nil {
		cfg.Bonsai = new(bonsai.Config)
	}
	if cfg.Sp1 == nil {
		cfg.Sp1 = new(sp1.Config)
	}
	if err := cfg.Bonsai.Init(); err != nil {
		return nil, logex.Trace(err)
	}
	if err := cfg.Sp1.Init(); err != nil {
		return nil, logex.Trace(err)
	}

	client := &ZkProofClient{ps: ps}

	if cfg.Bonsai.ApiKey != "" {
		bonsaiClient, err := bonsai.NewClient(cfg.Bonsai)
		if err != nil {
			return nil, logex.Trace(err)
		}
		client.Bonsai = bonsaiClient
	}

	if cfg.Sp1.PrivateKey != "" {
		sp1Client, err := sp1.NewClient(cfg.Sp1)
		if err != nil {
			return nil, logex.Trace(err)
		}
		client.Sp1 = sp1Client
	}

	return client, nil
}

// ProveQuote generates a zero-knowledge proof for the given quote and collateral
func (c *ZkProofClient) ProveQuote(ctx context.Context, ty ZkType, quote []byte, collateral *Collateral) (*ZkProof, error) {
	proof := &ZkProof{Type: ty}
	switch ty {
	case ZkTypeRiscZero:
		if c.Bonsai == nil {
			return nil, logex.NewError("BONSAI_API_KEY is required")
		}
		// Upload image to Bonsai if not already uploaded
		err := c.Bonsai.UploadImage(BONSAI_IMAGE_ID, BONSAI_DCAP_GUEST_ELF)
		if err != nil {
			return nil, logex.Trace(err)
		}
		// Generate input for Bonsai proof
		input := BonsaiGenerateInput(quote, collateral)
		// Generate Bonsai proof
		proveInfo, err := c.Bonsai.Prove(ctx, BONSAI_IMAGE_ID, input, bonsai.ReceiptGroth16)
		if err != nil {
			return nil, logex.Trace(err)
		}
		// Set proof output and proof data
		proof.Output = []byte(proveInfo.Receipt.Journal.Bytes)
		groth16 := proveInfo.Receipt.Inner.Groth16
		var selector [4]byte
		binary.LittleEndian.PutUint32(selector[:], groth16.VerifierParameters[0])
		proof.Proof = bonsai.Groth16Encode(selector, []byte(groth16.Seal))
	case ZkTypeSuccinct:
		if c.Sp1 == nil {
			return nil, logex.NewError("NETWORK_PRIVATE_KEY is required")
		}

		// Generate input for SP1 proof
		stdin := sp1.NewSP1StdinFromInput(Sp1GenerateInput(quote, collateral))
		// Generate SP1 proof
		res, err := c.Sp1.Prove(ctx, SP1_PROGRAM_VKHASH, stdin)
		if err != nil {
			return nil, logex.Trace(err)
		}
		// Set proof output and proof data
		proofBytes, err := res.Bytes()
		if err != nil {
			return nil, logex.Trace(err)
		}
		proof.Output = []byte(res.PublicValues.Buffer.Data)
		proof.Proof = proofBytes
	}
	return proof, nil
}
