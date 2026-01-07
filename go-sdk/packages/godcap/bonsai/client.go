package bonsai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/chzyer/logex"
)

type ReceiptKind uint8

const (
	ReceiptGroth16  ReceiptKind = 0
	ReceiptSuccinct ReceiptKind = 1
)

type Config struct {
	Url              string `json:"url"`
	ApiKey           string `json:"api_key"`
	Version          string `json:"version"`
	PollIntervalSecs int    `json:"poll_interval_secs"`
}

func (c *Config) Init() error {
	if c.Url == "" {
		c.Url = os.Getenv("BONSAI_API_URL")
	}
	if c.Url == "" {
		c.Url = "https://api.bonsai.xyz"
	}
	if c.Version == "" {
		c.Version = "2.0.1"
	}
	if c.ApiKey == "" {
		c.ApiKey = os.Getenv("BONSAI_API_KEY")
	}
	if c.PollIntervalSecs == 0 {
		c.PollIntervalSecs = 5
	}
	return nil
}

type Client struct {
	cfg *Config
}

func NewClient(cfg *Config) (*Client, error) {
	if err := cfg.Init(); err != nil {
		return nil, logex.Trace(err)
	}
	return &Client{cfg: cfg}, nil
}

type ProveInfo struct {
	/// receipt from the computation
	Receipt *Receipt
	/// stats about cycle counts of the execution
	Stats *SessionStats
}

func (c *Client) Prove(ctx context.Context, imageID string, input []byte, kind ReceiptKind) (*ProveInfo, error) {
	inputId, err := c.UploadInput(input)
	if err != nil {
		return nil, logex.Trace(err, "uploadInput")
	}
	sess, err := c.CreateSessionWithLimit(&ProofReq{
		Img:         imageID,
		Input:       inputId,
		Assumptions: []string{},
	})
	if err != nil {
		return nil, logex.Trace(err, "createSess")
	}
	polling := time.Duration(c.cfg.PollIntervalSecs) * time.Second
	proveInfo, err := sess.Poll(ctx, polling)
	if err != nil {
		return nil, logex.Trace(err)
	}
	if kind == ReceiptSuccinct {
		return proveInfo, nil
	}

	snarkSess, err := sess.CreateSnark(ctx)
	if err != nil {
		return nil, logex.Trace(err)
	}
	logex.Infof("create snark session: %v", snarkSess.uuid)

	receipt, err := snarkSess.Poll(ctx, polling)
	if err != nil {
		return nil, logex.Trace(err)
	}
	proveInfo.Receipt = receipt
	return proveInfo, nil
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

func (c *Client) api(method string, path string, body io.Reader, response interface{}) (int, error) {
	// defaults to BAD_REQUEST error if failed before http call
	statusCode := http.StatusBadRequest

	req, err := http.NewRequest(method, fmt.Sprintf("%v/%v", c.cfg.Url, path), body)
	if err != nil {
		return statusCode, logex.Trace(err)
	}
	if c.cfg.ApiKey == "" {
		return statusCode, logex.NewError("BONSAI_API_KEY is required")
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("x-api-key", c.cfg.ApiKey)
	req.Header.Set("x-risc0-version", c.cfg.Version)
	httpResponse, err := http.DefaultClient.Do(req)

	statusCode = httpResponse.StatusCode

	if err != nil {
		return statusCode, logex.Trace(err)
	}
	defer httpResponse.Body.Close()
	httpBody, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		return statusCode, logex.Trace(err)
	}

	if httpResponse.StatusCode/100 != 2 {
		return statusCode, logex.NewErrorf("http remote error: %v", string(httpBody))
	}
	if response != nil && len(httpBody) != 0 {
		if err := json.Unmarshal(httpBody, response); err != nil {
			return statusCode, logex.Trace(err)
		}
	}
	return statusCode, nil
}

type UploadResponse struct {
	Url  string `json:"url"`
	Uuid string `json:"uuid"`
}

func (c *Client) UploadInput(input []byte) (string, error) {
	var response UploadResponse
	if _, err := c.api(http.MethodGet, "inputs/upload", nil, &response); err != nil {
		return "", logex.Trace(err)
	}
	if _, err := c.s3(http.MethodPut, response.Url, bytes.NewReader(input)); err != nil {
		return "", logex.Trace(err)
	}
	return response.Uuid, nil
}

func (c *Client) UploadImage(imageID string, elf []byte) error {
	var response UploadResponse
	statusCode, err := c.api(http.MethodGet, "images/upload/"+imageID, nil, &response)
	if err != nil {
		return logex.Trace(err)
	}

	if statusCode == http.StatusOK {
		// upload the image
		if _, err := c.s3(http.MethodPut, response.Url, bytes.NewReader(elf)); err != nil {
			return logex.Trace(err)
		}
	}

	return nil
}

type ProofReq struct {
	/// Image UUID
	Img string `json:"img"`
	/// Input UUID
	Input string `json:"input"`
	/// List of receipt UUIDs
	Assumptions []string `json:"assumptions"`
	/// Execute Only Mode
	ExecuteOnly bool `json:"execute_only"`
	/// executor cycle limit
	ExecCycleLimit uint64 `json:"exec_cycle_limit,omitempty"`
}

type CreateSessRes struct {
	/// Generated UUID for the session
	Uuid string `json:"uuid"`
}

type SnarkSession struct {
	uuid   string
	client *Client
}

func (s *SnarkSession) Status(ctx context.Context) (*SnarkStatusRes, error) {
	var res SnarkStatusRes
	if _, err := s.client.api(http.MethodGet, fmt.Sprintf("snark/status/%v", s.uuid), nil, &res); err != nil {
		return nil, logex.Trace(err, "SessionStatus")
	}
	return &res, nil
}

func (s *SnarkSession) Poll(ctx context.Context, interval time.Duration) (*Receipt, error) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	errRetryTime := 3
	for {
		select {
		case <-ctx.Done():
			return nil, logex.Trace(ctx.Err())
		case <-ticker.C:
			status, err := s.Status(ctx)
			if err != nil {
				if errRetryTime == 0 {
					return nil, logex.Trace(err)
				}
				logex.Error(err)
				errRetryTime--
				continue
			}
			switch status.Status {
			case "RUNNING":
				logex.Infof("SnarkSession %v is running", s.uuid)
				continue
			case "SUCCEEDED":
				if status.Output == "" {
					return nil, logex.NewErrorf("missing receipt: %v", status)
				}
				data, err := s.client.s3(http.MethodGet, status.Output, nil)
				if err != nil {
					return nil, logex.Trace(err)
				}

				receipt, err := NewReceiptFromBincode(data)
				if err != nil {
					return nil, logex.Trace(err)
				}
				return receipt, nil
			default:
				return nil, logex.NewErrorf("unexpected status: %v", status)
			}
		}
	}
}

type Session struct {
	uuid   string
	client *Client
}

func (c *Client) CreateSessionWithLimit(proof *ProofReq) (*Session, error) {
	req, _ := json.Marshal(proof)
	var response CreateSessRes
	if _, err := c.api(http.MethodPost, "sessions/create", bytes.NewReader(req), &response); err != nil {
		return nil, logex.Trace(err)
	}
	return &Session{uuid: response.Uuid, client: c}, nil
}

type SessionStatusRes struct {
	/// Current status
	///
	/// values: `[ RUNNING | SUCCEEDED | FAILED | TIMED_OUT | ABORTED ]`
	Status string `json:"status"`
	/// Final receipt download URL
	///
	/// If the status == `SUCCEEDED` then this should be present
	ReceiptURL string `json:"receipt_url,omitempty"`
	/// Session Error message
	///
	/// If the session is not `RUNNING` or `SUCCEEDED`, this is the error
	/// raised from within bonsai, otherwise it is [None].
	ErrorMsg string `json:"error_msg,omitempty"`
	/// Session Proving State
	///
	/// If the status is `RUNNING`, this is a indication of where in the
	/// proving pipeline the session currently is, otherwise it is [None].
	/// Possible states in order, include:
	/// * `Setup`
	/// * `Executor`
	/// * `ProveSegments: N/M`
	/// * `Planner`
	/// * `Recursion`
	/// * `RecursionJoin: N/M`
	/// * `Resolve`
	/// * `Finalize`
	/// * `InProgress`
	State string `json:"state"`
	/// Elapsed Time
	///
	/// Elapsed time for a given session, in seconds
	ElapsedTime float64 `json:"elapsed_time,omitempty"`
	/// Successful Session Stats
	///
	/// Stats for a given successful session. Returns:
	/// - Count of segments in this proof request
	/// - User cycles run within guest, slightly below total overhead cycles
	Stats *SessionStats `json:"stats,omitempty"`
}

type SessionStats struct {
	/// Count of segments in this proof request
	Segments int `json:"segments"`
	/// Total cycles run within guest
	TotalCycles uint64 `json:"total_cycles"`
	/// User cycles run within guest, slightly below total overhead cycles
	Cycles uint64 `json:"cycles"`
}

func (s *Session) Status(ctx context.Context) (*SessionStatusRes, error) {
	var res SessionStatusRes
	if _, err := s.client.api(http.MethodGet, fmt.Sprintf("sessions/status/%v", s.uuid), nil, &res); err != nil {
		return nil, logex.Trace(err, "SessionStatus")
	}
	return &res, nil
}

type SnarkReq struct {
	/// Existing Session ID from [super::SessionId]
	SessionID string `json:"session_id"`
}

type SnarkStatusRes struct {
	/// Current status
	///
	/// values: `[ RUNNING | SUCCEEDED | FAILED | TIMED_OUT | ABORTED ]`
	Status string `json:"status"`
	/// SNARK receipt download URL
	///
	/// Url to download the snark (receipt `risc0::Receipt` bincode encoded)
	Output string `json:"output"`
	/// Snark Error message
	///
	/// If the SNARK status is not `RUNNING` or `SUCCEEDED`, this is the
	/// error raised from within bonsai.
	ErrorMsg *string `json:"error_msg"`
}

func (s *Session) CreateSnark(ctx context.Context) (*SnarkSession, error) {
	data, _ := json.Marshal(&SnarkReq{SessionID: s.uuid})
	var response CreateSessRes
	if _, err := s.client.api(http.MethodPost, "snark/create", bytes.NewReader(data), &response); err != nil {
		return nil, logex.Trace(err)
	}
	return &SnarkSession{uuid: response.Uuid, client: s.client}, nil
}

func (s *Session) Poll(ctx context.Context, interval time.Duration) (*ProveInfo, error) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	errRetryTime := 3
	for {
		select {
		case <-ctx.Done():
			return nil, logex.Trace(ctx.Err())
		case <-ticker.C:
			status, err := s.Status(ctx)
			if err != nil {
				if errRetryTime == 0 {
					return nil, logex.Trace(err)
				}
				logex.Error(err)
				errRetryTime--
				continue
			}
			switch status.Status {
			case "RUNNING":
				logex.Infof("Session %v is running", s.uuid)
				continue
			case "SUCCEEDED":
				if status.ReceiptURL == "" {
					return nil, logex.NewErrorf("missing receipt: %v", status)
				}
				logex.Infof("stat: %#v", status.Stats)
				data, err := s.client.s3(http.MethodGet, status.ReceiptURL, nil)
				if err != nil {
					return nil, logex.Trace(err)
				}

				receipt, err := NewReceiptFromBincode(data)
				if err != nil {
					return nil, logex.Trace(err)
				}
				return &ProveInfo{
					Receipt: receipt,
					Stats:   status.Stats,
				}, nil
			default:
				return nil, logex.NewErrorf("unexpected status: %v", status)
			}
		}
	}
}
