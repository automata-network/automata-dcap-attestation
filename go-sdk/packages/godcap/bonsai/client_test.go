package bonsai

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestAPIRequestError(t *testing.T) {
	originalClient := http.DefaultClient
	t.Cleanup(func() {
		http.DefaultClient = originalClient
	})

	requestErr := errors.New("request failed")
	http.DefaultClient = &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, requestErr
		}),
	}

	client := &Client{cfg: &Config{
		Url:    "https://bonsai.example",
		ApiKey: "test-api-key",
	}}
	statusCode, err := client.api(http.MethodGet, "status", nil, nil)
	if err == nil {
		t.Fatal("expected request error")
	}
	if !strings.Contains(err.Error(), requestErr.Error()) {
		t.Fatalf("expected error to contain %q, got %q", requestErr, err)
	}
	if statusCode != http.StatusBadRequest {
		t.Fatalf("expected status code %d when request fails, got %d", http.StatusBadRequest, statusCode)
	}
}
