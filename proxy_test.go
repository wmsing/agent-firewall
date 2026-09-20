package main

import (
	"github.com/wmsing/agent-firewall/eval"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestMaxBodyReturns413(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	u, err := url.Parse(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	h := NewFirewallHandler(u, eval.MockRiskEvaluator{})

	srv := httptest.NewServer(h)
	defer srv.Close()

	big := strings.Repeat("x", maxBodyBytes+1)
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api", strings.NewReader(big))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d want 413", resp.StatusCode)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
}
