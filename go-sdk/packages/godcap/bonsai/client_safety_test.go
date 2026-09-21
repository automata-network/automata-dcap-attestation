package bonsai

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type testTransport func(*http.Request) (*http.Response, error)

func (f testTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func withTransport(t *testing.T, transport testTransport) *Client {
	old := http.DefaultClient
	http.DefaultClient = &http.Client{Transport: transport}
	t.Cleanup(func() { http.DefaultClient = old })
	return &Client{cfg: &Config{Url: "https://bonsai.invalid", ApiKey: "test-only"}}
}

func TestAPITransportFailureReturnsError(t *testing.T) {
	c := withTransport(t, func(*http.Request) (*http.Response, error) { return nil, errors.New("transport failed") })
	if status, err := c.api(http.MethodGet, "test", nil, nil); err == nil || status != http.StatusBadRequest {
		t.Fatalf("status=%d error=%v", status, err)
	}
}

func TestAPIResponseHandling(t *testing.T) {
	for _, test := range []struct {
		name, body string
		status     int
		wantErr    bool
	}{
		{"json", `{"uuid":"ok"}`, 200, false},
		{"empty", "", 204, false},
		{"remote-error", "denied", 403, true},
		{"bad-json", "{", 200, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := withTransport(t, func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: test.status, Body: io.NopCloser(strings.NewReader(test.body)), Header: make(http.Header)}, nil
			})
			var response UploadResponse
			status, err := c.api(http.MethodGet, "test", nil, &response)
			if status != test.status || (err != nil) != test.wantErr {
				t.Fatalf("status=%d error=%v", status, err)
			}
			if test.name == "json" && response.Uuid != "ok" {
				t.Fatal("lost response")
			}
		})
	}
}
