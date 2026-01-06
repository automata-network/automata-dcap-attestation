package sp1

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/bincode"
	"github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/sp1/sp1_proto"
	"github.com/chzyer/logex"
	"github.com/ethereum/go-ethereum/common"
	"google.golang.org/protobuf/proto"
)

// GetNonceRequest represents a request to get the nonce for an account.
type GetNonceRequest struct {
	Address []byte `json:"address"`
}

// GetNonceResponse represents the response containing the nonce.
type GetNonceResponse struct {
	Nonce uint64 `json:"nonce,string"`
}

// RpcGetNonce retrieves the nonce for the client's public address.
func (c *Client) RpcGetNonce(ctx context.Context) (uint64, error) {
	addr := c.Public()
	res, err := c.conn.GetNonce(ctx, &sp1_proto.GetNonceRequest{Address: addr[:]})
	if err != nil {
		return 0, logex.Trace(err)
	}
	return res.Nonce, nil
}

// AuctionParams holds the default auction parameters fetched from the network.
type AuctionParams struct {
	Domain         []byte
	Auctioneer     []byte
	Executor       []byte
	Verifier       []byte
	Treasury       []byte
	MaxPricePerPgu string
	BaseFee        string
}

// RpcGetProofRequestParams retrieves the default auction parameters for a given proof mode.
func (c *Client) RpcGetProofRequestParams(ctx context.Context, mode sp1_proto.ProofMode) (*AuctionParams, error) {
	res, err := c.conn.GetProofRequestParams(ctx, &sp1_proto.GetProofRequestParamsRequest{Mode: mode})
	if err != nil {
		return nil, logex.Trace(err)
	}
	return &AuctionParams{
		Domain:         res.Domain,
		Auctioneer:     res.Auctioneer,
		Executor:       res.Executor,
		Verifier:       res.Verifier,
		Treasury:       res.Treasury,
		MaxPricePerPgu: res.MaxPricePerPgu,
		BaseFee:        res.BaseFee,
	}, nil
}

// RpcGetProversByUptime retrieves the list of provers by uptime for the whitelist.
func (c *Client) RpcGetProversByUptime(ctx context.Context, highAvailabilityOnly bool) ([][]byte, error) {
	res, err := c.conn.GetProversByUptime(ctx, &sp1_proto.GetProversByUptimeRequest{
		HighAvailabilityOnly: highAvailabilityOnly,
	})
	if err != nil {
		return nil, logex.Trace(err)
	}
	return res.Provers, nil
}

// CreateProofRequest represents a request to create a proof.
type CreateProofRequest struct {
	/// The signature of the message.
	Signature []byte `json:"signature"`
	/// The nonce for the account.
	Nonce uint64 `json:"nonce,string"`
	/// The mode for proof generation.
	Mode uint32 `json:"mode"`
	/// The deadline for the proof request, signifying the latest time a fulfillment would be valid.
	Deadline uint64 `json:"deadline,string"`
	/// The SP1 circuit version to use for the proof.
	CircuitVersion string `json:"circuit_version"`
}

// CreateProofResponse represents the response containing proof details.
type CreateProofResponse struct {
	/// The proof identifier.
	ProofId string `json:"proof_id"`
	/// The URL to upload the ELF file.
	ProgramUrl string `json:"program_url"`
	/// The URL to upload the standard input (stdin).
	StdinUrl string `json:"stdin_url"`
}

func (c *Client) CreateArtifact(ctx context.Context, aty sp1_proto.ArtifactType, content []byte) (string, error) {
	sig, err := EIP191SignHash(c.auth.key, []byte("create_artifact"))
	if err != nil {
		return "", logex.Trace(err)
	}
	rsp, err := c.artifact.CreateArtifact(ctx, &sp1_proto.CreateArtifactRequest{
		Signature:    sig,
		ArtifactType: aty,
	})
	if err != nil {
		return "", logex.Trace(err)
	}
	resp, err := c.s3(http.MethodPut, rsp.ArtifactPresignedUrl, bytes.NewReader(content))
	if err != nil {
		return "", logex.Trace(err)
	}
	_ = resp
	return rsp.ArtifactUri, nil
}

// Prove creates and submits a proof, then polls for the proof status.
func (c *Client) Prove(ctx context.Context, programVkHash common.Hash, stdin *SP1Stdin) (*SP1ProofWithPublicValues, error) {
	requestId, err := c.CreateProof(ctx, programVkHash, stdin, sp1_proto.ProofMode_Groth16)
	if err != nil {
		return nil, logex.Trace(err)
	}
	proof, err := c.PollProof(ctx, requestId, time.Duration(c.cfg.PollIntervalSecs)*time.Second)
	if err != nil {
		return nil, logex.Trace(err)
	}
	return proof, nil
}

// CreateProof creates a proof and uploads the necessary files.
func (c *Client) CreateProof(ctx context.Context, programVkHash common.Hash, stdin *SP1Stdin, mode sp1_proto.ProofMode) ([]byte, error) {
	nonce, err := c.RpcGetNonce(ctx)
	if err != nil {
		return nil, logex.Trace(err)
	}
	logex.Infof("account=%v, nonce: %v", c.Public(), nonce)

	// Fetch auction parameters from the network
	auctionParams, err := c.RpcGetProofRequestParams(ctx, mode)
	if err != nil {
		return nil, logex.Trace(err)
	}

	// Fetch whitelist of provers by uptime
	whitelist, err := c.RpcGetProversByUptime(ctx, false)
	if err != nil {
		return nil, logex.Trace(err)
	}

	stdinUrl, err := c.CreateArtifact(ctx, sp1_proto.ArtifactType_Stdin, stdin.Bincode())
	if err != nil {
		return nil, logex.Trace(err)
	}

	reqBody := &sp1_proto.RequestProofRequestBody{
		Nonce:            nonce,
		Version:          fmt.Sprintf("sp1-%v", c.cfg.Version),
		VkHash:           programVkHash[:],
		Mode:             mode,
		Strategy:         c.cfg.Strategy,
		StdinUri:         stdinUrl,
		Deadline:         uint64(time.Now().Unix()) + c.cfg.Timeout,
		CycleLimit:       c.cfg.CycleLimit,
		GasLimit:         c.cfg.GasLimit,
		MinAuctionPeriod: 0,
		Whitelist:        whitelist,
		Domain:           auctionParams.Domain,
		Auctioneer:       auctionParams.Auctioneer,
		Executor:         auctionParams.Executor,
		Verifier:         auctionParams.Verifier,
		Treasury:         auctionParams.Treasury,
		BaseFee:          auctionParams.BaseFee,
		MaxPricePerPgu:   auctionParams.MaxPricePerPgu,
		Variant:          sp1_proto.TransactionVariant_RequestVariant,
	}
	reqBodyMsg, err := proto.Marshal(reqBody)
	if err != nil {
		return nil, logex.Trace(err)
	}
	reqSig, err := EIP191SignHash(c.auth.key, reqBodyMsg)
	if err != nil {
		return nil, logex.Trace(err)
	}
	response, err := c.conn.RequestProof(ctx, &sp1_proto.RequestProofRequest{
		Format:    sp1_proto.MessageFormat_Binary,
		Signature: reqSig,
		Body:      reqBody,
	})
	if err != nil {
		return nil, logex.Trace(err)
	}
	return response.Body.RequestId, nil
}

// RpcGetProofStatus retrieves the status of the proof with the given proof ID.
func (c *Client) RpcGetProofStatus(ctx context.Context, requestId []byte) (*sp1_proto.GetProofRequestStatusResponse, error) {
	res, err := c.conn.GetProofRequestStatus(ctx, &sp1_proto.GetProofRequestStatusRequest{RequestId: requestId})
	if err != nil {
		return nil, logex.Trace(err)
	}
	return res, nil
}

// SP1ProofWithPublicValues represents a proof along with its public values.
type SP1ProofWithPublicValues struct {
	Proof        SP1Proof
	PublicValues SP1PublicValues
	Sp1Version   bincode.String
}

// Bytes serializes the proof with public values into bytes.
func (p *SP1ProofWithPublicValues) Bytes() ([]byte, error) {
	switch p.Proof.Type.Raw() {
	case 3: // Groth16
		proof := p.Proof.Groth16
		bytes := make([]byte, 0, 4+len(proof.EncodedProof))
		bytes = append(bytes, proof.Groth16VkeyHash[:4]...)
		decodedProof, err := hex.DecodeString(string(proof.EncodedProof))
		if err != nil {
			return nil, logex.Trace(err)
		}
		bytes = append(bytes, decodedProof...)
		return bytes, nil
	default:
		return nil, logex.NewErrorf("unsupported proof mode: %v", p.Proof.Type)
	}
}

// New creates a new instance of SP1ProofWithPublicValues.
func (p *SP1ProofWithPublicValues) New() bincode.FromBin {
	return new(SP1ProofWithPublicValues)
}

// String returns a string representation of SP1ProofWithPublicValues.
func (p *SP1ProofWithPublicValues) String() string {
	return fmt.Sprintf("SP1ProofWithPublicValues{proof: %v, public_values: %v, sp1_version: %v}", p.Proof.String(), p.PublicValues.String(), p.Sp1Version.String())
}

// FromBin deserializes the proof with public values from bytes.
func (p *SP1ProofWithPublicValues) FromBin(data []byte) ([]byte, error) {
	var err error
	data, err = p.Proof.FromBin(data)
	if err != nil {
		return nil, logex.Trace(err)
	}
	data, err = p.PublicValues.FromBin(data)
	if err != nil {
		return nil, logex.Trace(err)
	}
	data, err = p.Sp1Version.FromBin(data)
	if err != nil {
		return nil, logex.Trace(err)
	}
	return data, nil
}

// SP1Proof represents a proof with its type and specific proof data.
type SP1Proof struct {
	Type    bincode.U32
	Groth16 *Groth16Bn254Proof
}

// New creates a new instance of SP1Proof.
func (p *SP1Proof) New() bincode.FromBin {
	return new(SP1Proof)
}

// String returns a string representation of SP1Proof.
func (p *SP1Proof) String() string {
	if uint32(p.Type) == 3 {
		return fmt.Sprintf("SP1Proof:Groth16(%v)", p.Groth16.String())
	} else {
		return "unknown SP1Proof"
	}
}

// FromBin deserializes the proof from bytes.
func (p *SP1Proof) FromBin(data []byte) ([]byte, error) {
	var err error
	data, err = p.Type.FromBin(data)
	if err != nil {
		return nil, logex.Trace(err)
	}
	switch p.Type.Raw() {
	case 3:
		p.Groth16 = p.Groth16.New().(*Groth16Bn254Proof)
		data, err = p.Groth16.FromBin(data)
		if err != nil {
			return nil, logex.Trace(err)
		}
	default:
		return nil, bincode.ErrUnexpectEnum.Format(p, p.Type)
	}
	return data, nil
}

// Groth16Bn254Proof represents a Groth16 proof with specific data.
type Groth16Bn254Proof struct {
	PublicInputs    [2]bincode.String
	EncodedProof    bincode.String
	RawProof        bincode.String
	Groth16VkeyHash bincode.Bytes32
}

// New creates a new instance of Groth16Bn254Proof.
func (p *Groth16Bn254Proof) New() bincode.FromBin {
	return new(Groth16Bn254Proof)
}

// String returns a string representation of Groth16Bn254Proof.
func (p *Groth16Bn254Proof) String() string {
	return fmt.Sprintf("Groth16Bn254Proof{public_inputs: %v, encoded_proof: %v, raw_proof: %v, groth16_vkey_hash: %v}", p.PublicInputs, p.EncodedProof, p.RawProof, p.Groth16VkeyHash)
}

// FromBin deserializes the Groth16 proof from bytes.
func (p *Groth16Bn254Proof) FromBin(data []byte) ([]byte, error) {
	return bincode.UnmarshalFields(data, []bincode.FromBin{&p.PublicInputs[0], &p.PublicInputs[1], &p.EncodedProof, &p.RawProof, &p.Groth16VkeyHash})
}

// Buffer represents a buffer with binary data.
type Buffer struct {
	Data bincode.Bytes
}

// String returns a string representation of Buffer.
func (b *Buffer) String() string {
	return fmt.Sprintf("Buffer{data: %v}", b.Data.String())
}

// FromBin deserializes the buffer from bytes.
func (b *Buffer) FromBin(data []byte) ([]byte, error) {
	return bincode.UnmarshalFields(data, []bincode.FromBin{&b.Data})
}

// SP1PublicValues represents public values associated with a proof.
type SP1PublicValues struct {
	Buffer Buffer
}

// New creates a new instance of SP1PublicValues.
func (v *SP1PublicValues) New() bincode.FromBin {
	return new(SP1PublicValues)
}

// String returns a string representation of SP1PublicValues.
func (v *SP1PublicValues) String() string {
	return fmt.Sprintf("SP1PublicValues{buffer: %v}", v.Buffer.String())
}

// FromBin deserializes the public values from bytes.
func (v *SP1PublicValues) FromBin(data []byte) ([]byte, error) {
	return v.Buffer.FromBin(data)
}

// PollProof polls the status of the proof until it is fulfilled or an error occurs.
func (c *Client) PollProof(ctx context.Context, requestId []byte, interval time.Duration) (*SP1ProofWithPublicValues, error) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	errRetryTime := 3
	isClaimed := false
	for {
		select {
		case <-ctx.Done():
			return nil, logex.Trace(ctx.Err())
		case <-ticker.C:
			status, err := c.RpcGetProofStatus(ctx, requestId)
			if err != nil {
				if errRetryTime == 0 {
					return nil, logex.Trace(err)
				}
				logex.Error(err)
				errRetryTime--
				continue
			}
			switch status.FulfillmentStatus {
			case sp1_proto.FulfillmentStatus_Fulfilled:
				if status.ProofUri == nil {
					return nil, logex.NewErrorf("missing receipt: %v", status)
				}
				proofBytes, err := c.s3(http.MethodGet, *status.ProofUri, nil)
				if err != nil {
					return nil, logex.Trace(err)
				}
				res, err := bincode.Unmarshal[*SP1ProofWithPublicValues](proofBytes)
				if err != nil {
					return nil, logex.Trace(err)
				}
				return res, nil
			case sp1_proto.FulfillmentStatus_Assigned:
				if !isClaimed {
					logex.Infof("Proof request assigned, requestId=%x", requestId)
					isClaimed = true
				}
			case sp1_proto.FulfillmentStatus_Unfulfillable:
				return nil, logex.NewErrorf(
					"Proof generation failed: %v",
					status,
				)
			default:
				logex.Infof("requestId %x is running: %v", requestId, status)
			}
		}
	}
}

// SP1Stdin represents the standard input for SP1.
type SP1Stdin struct {
	Buffer bincode.Collection[*bincode.Bytes]
	Ptr    bincode.U64
	Proofs bincode.Collection[*bincode.U32]
}

// NewSP1StdinFromInput creates a new SP1Stdin from the given input bytes.
func NewSP1StdinFromInput(input []byte) *SP1Stdin {
	return &SP1Stdin{
		Buffer: bincode.Collection[*bincode.Bytes]([]*bincode.Bytes{(*bincode.Bytes)(&input)}),
	}
}

// New creates a new instance of SP1Stdin.
func (s *SP1Stdin) New() bincode.FromBin {
	return new(SP1Stdin)
}

// String returns a string representation of SP1Stdin.
func (s *SP1Stdin) String() string {
	return fmt.Sprintf("SP1Stdin(%v)", len(s.Buffer))
}

// FromBin deserializes the standard input from bytes.
func (s *SP1Stdin) FromBin(data []byte) ([]byte, error) {
	return bincode.UnmarshalFields(data, []bincode.FromBin{
		&s.Buffer, &s.Ptr, &s.Proofs,
	})
}

// Bincode serializes the standard input into bytes.
func (s *SP1Stdin) Bincode() []byte {
	var buf []byte
	var led = binary.LittleEndian
	// collection
	buf = led.AppendUint64(buf, uint64(len(s.Buffer)))
	for _, buffer := range s.Buffer {
		buf = append(buf, buffer.Bincode()...)
	}
	// ptr
	buf = led.AppendUint64(buf, 0)
	// proofs
	buf = led.AppendUint64(buf, 0)
	return buf
}
