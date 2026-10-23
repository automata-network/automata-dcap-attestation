package bonsai

import (
	"context"
	"net/http"
	"testing"
)

func TestSessionRequestsPropagateContext(t *testing.T) {
	for _, name := range []string{"session status", "snark status", "create snark"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			originalClient := http.DefaultClient
			t.Cleanup(func() { http.DefaultClient = originalClient })
			http.DefaultClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.Context().Err() != context.Canceled {
					t.Error("HTTP request did not receive the canceled context")
				}
				return nil, context.Canceled
			})}
			client := &Client{cfg: &Config{Url: "https://bonsai.example", ApiKey: "test"}}
			var err error
			switch name {
			case "session status":
				_, err = (&Session{uuid: "test", client: client}).Status(ctx)
			case "snark status":
				_, err = (&SnarkSession{uuid: "test", client: client}).Status(ctx)
			case "create snark":
				_, err = (&Session{uuid: "test", client: client}).CreateSnark(ctx)
			}
			if err == nil {
				t.Fatal("expected a cancellation error")
			}
		})
	}
}
