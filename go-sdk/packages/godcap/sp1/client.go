package sp1

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/sp1/sp1_proto"
	"github.com/chzyer/logex"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

type ProofStatus uint32

const (
	/// Unspecified or invalid status.
	ProofUnspecifiedStatus ProofStatus = iota
	/// The proof request has been created but is awaiting the requester to submit it.
	ProofPreparing
	/// The proof request has been submitted and is awaiting a prover to claim it.
	ProofRequested
	/// The proof request has been claimed and is awaiting a prover to fulfill it.
	ProofClaimed
	/// The proof request was previously claimed but has now been unclaimed.
	ProofUnclaimed
	/// The proof request has been fulfilled and is available for download.
	ProofFulfilled
)

type Config struct {
	Rpc              string `json:"rpc"`
	PrivateKey       string `json:"private_key"`
	TimeoutSecs      int    `json:"timeout_secs"`
	PollIntervalSecs int    `json:"poll_interval_secs"`
	Version          string `json:"version"`
	CycleLimit       uint64 `json:"cycle_limit"`
	Timeout          uint64 `json:"timeout"`

	Strategy sp1_proto.FulfillmentStrategy `json:"strategy"`
}

func (c *Config) Init() error {
	if c.Rpc == "" {
		c.Rpc = os.Getenv("PROVER_NETWORK_RPC")
	}
	if c.Rpc == "" {
		c.Rpc = "https://rpc.mainnet.succinct.xyz"
	}
	if c.PrivateKey == "" {
		c.PrivateKey = os.Getenv("NETWORK_PRIVATE_KEY")
	}
	if c.TimeoutSecs == 0 {
		c.TimeoutSecs = 30
	}
	if c.PollIntervalSecs == 0 {
		c.PollIntervalSecs = 5
	}
	if c.Version == "" {
		c.Version = "v5.2.1"
	}
	if c.CycleLimit == 0 {
		c.CycleLimit = 1_000_000_000_000 // Mainnet default
	}
	if c.Timeout == 0 {
		c.Timeout = 14400
	}
	if c.Strategy == sp1_proto.FulfillmentStrategy_UnspecifiedFulfillmentStrategy {
		c.Strategy = sp1_proto.FulfillmentStrategy_Auction
	}
	return nil
}

type Client struct {
	cfg      *Config
	conn     sp1_proto.ProverNetworkClient
	artifact sp1_proto.ArtifactStoreClient
	auth     *EIP712Auth
}

func NewClient(cfg *Config) (*Client, error) {
	if err := cfg.Init(); err != nil {
		return nil, logex.Trace(err)
	}
	key, err := crypto.HexToECDSA(cfg.PrivateKey)
	if err != nil {
		return nil, logex.Trace(err)
	}

	conn, err := dialGrpcConn(cfg.Rpc)
	if err != nil {
		return nil, logex.Trace(err)
	}
	grpcClient := sp1_proto.NewProverNetworkClient(conn)
	artifact := sp1_proto.NewArtifactStoreClient(conn)

	client := &Client{
		cfg:      cfg,
		conn:     grpcClient,
		artifact: artifact,
		auth:     NewEIP712Auth(key),
	}
	return client, nil
}

func dialGrpcConn(rpcEndpoint string) (*grpc.ClientConn, error) {
	rpcUrl, err := url.Parse(rpcEndpoint)
	if err != nil {
		return nil, logex.Trace(err)
	}
	port := "80"
	var opts []grpc.DialOption
	if rpcUrl.Port() != "" {
		port = rpcUrl.Port()
	} else if rpcUrl.Scheme == "https" {
		port = "443"
	}
	if rpcUrl.Scheme == "https" {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(nil)))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
	conn, err := grpc.NewClient(fmt.Sprintf("%v:%v", rpcUrl.Host, port), opts...)
	if err != nil {
		return nil, logex.Trace(err)
	}
	return conn, nil
}

func (c *Client) Public() common.Address {
	return crypto.PubkeyToAddress(c.auth.key.PublicKey)
}

func (c *Client) s3(method string, url string, body io.Reader) ([]byte, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, logex.Trace(err)
	}
	httpResponse, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, logex.Trace(err)
	}
	defer httpResponse.Body.Close()
	httpBody, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, logex.Trace(err)
	}
	if httpResponse.StatusCode/100 != 2 {
		return nil, logex.NewErrorf("http remote error: %v", string(httpBody))
	}
	return httpBody, nil
}
