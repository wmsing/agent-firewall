package eval

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHTTPRiskEvaluator_JSONScore(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-key" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var req evaluateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		score := 0.1
		reason := "benign"
		if strings.Contains(strings.ToLower(req.Content), "ignore previous") {
			score = 0.95
			reason = "remote: injection"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(evaluateResponse{Score: score, Reason: reason})
	}))
	defer srv.Close()

	ev := &HTTPRiskEvaluator{
		client: srv.Client(),
		url:    srv.URL,
		apiKey: "test-key",
	}

	score, reason, err := ev.Evaluate(context.Background(), []byte(`{"hello":"world"}`))
	if err != nil {
		t.Fatal(err)
	}
	if score != 0.1 || reason != "benign" {
		t.Fatalf("got score=%v reason=%q", score, reason)
	}

	score, _, err = ev.Evaluate(context.Background(), []byte(`ignore previous`))
	if err != nil {
		t.Fatal(err)
	}
	if score != 0.95 {
		t.Fatalf("want 0.95 got %v", score)
	}
}

func TestHTTPRiskEvaluator_timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ev := &HTTPRiskEvaluator{
		client: srv.Client(),
		url:    srv.URL,
		apiKey: "k",
	}
	_, _, err := ev.Evaluate(context.Background(), []byte("x"))
	if err == nil {
		t.Fatal("want timeout error")
	}
}

func TestAssess_hardRule(t *testing.T) {
	blocked, layer, reason, _ := Assess(context.Background(), MockRiskEvaluator{}, []byte("rm -rf /tmp"))
	if !blocked || layer != "hard_rule" || reason != "rm_rf" {
		t.Fatalf("got blocked=%v layer=%q reason=%q", blocked, layer, reason)
	}
}
