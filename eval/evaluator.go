package eval

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

const RiskThreshold = 0.8

const evaluatorHTTPTimeout = 300 * time.Millisecond

type RiskEvaluator interface {
	Evaluate(ctx context.Context, body []byte) (score float64, reason string, err error)
}

func MatchHardRule(body []byte) (matched bool, rule string) {
	text := string(body)
	for _, hr := range hardRules {
		if hr.pattern.MatchString(text) {
			return true, hr.name
		}
	}
	return false, ""
}

// Assess runs hard rules then semantic scoring (fail-closed on evaluator error).
func Assess(ctx context.Context, ev RiskEvaluator, body []byte) (blocked bool, layer, reason string, score *float64) {
	if matched, rule := MatchHardRule(body); matched {
		return true, "hard_rule", rule, nil
	}
	s, r, err := ev.Evaluate(ctx, body)
	if err != nil {
		return true, "semantic", "evaluator error", nil
	}
	if s >= RiskThreshold {
		return true, "semantic", r, &s
	}
	return false, "", r, &s
}

type MockRiskEvaluator struct{}

func (MockRiskEvaluator) Evaluate(_ context.Context, body []byte) (float64, string, error) {
	lower := strings.ToLower(string(body))
	switch {
	case strings.Contains(lower, "ignore previous"):
		return 0.95, "prompt_injection: ignore previous", nil
	case strings.Contains(lower, "exfiltrate"):
		return 0.95, "data_exfiltration keyword", nil
	case strings.Contains(lower, ".env"):
		return 0.95, "secrets path reference", nil
	default:
		return 0.1, "benign", nil
	}
}

type HTTPRiskEvaluator struct {
	client *http.Client
	url    string
	apiKey string
}

type evaluateRequest struct {
	Content string `json:"content"`
}

type evaluateResponse struct {
	Score  float64 `json:"score"`
	Reason string  `json:"reason"`
}

func (h *HTTPRiskEvaluator) Evaluate(ctx context.Context, body []byte) (float64, string, error) {
	ctx, cancel := context.WithTimeout(ctx, evaluatorHTTPTimeout)
	defer cancel()

	payload, err := json.Marshal(evaluateRequest{Content: string(body)})
	if err != nil {
		return 0, "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.url, bytes.NewReader(payload))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+h.apiKey)

	resp, err := h.client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return 0, "", fmt.Errorf("evaluator HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}

	var out evaluateResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return 0, "", err
	}
	return out.Score, out.Reason, nil
}

type fallbackRiskEvaluator struct {
	primary  RiskEvaluator
	fallback RiskEvaluator
}

func (f *fallbackRiskEvaluator) Evaluate(ctx context.Context, body []byte) (float64, string, error) {
	score, reason, err := f.primary.Evaluate(ctx, body)
	if err == nil {
		return score, reason, nil
	}
	log.Printf("evaluator: primary failed (%v), using TypeSafe fallback", err)
	return f.fallback.Evaluate(ctx, body)
}

func newHTTPRiskEvaluator(apiURL, key string) *HTTPRiskEvaluator {
	return &HTTPRiskEvaluator{
		client: &http.Client{Timeout: evaluatorHTTPTimeout + 50*time.Millisecond},
		url:    apiURL,
		apiKey: key,
	}
}

// NewRiskEvaluator: EVALUATOR_* HTTP first; with TYPESAFE_API_KEY also set, fallback to TypeSafe on primary error; else TypeSafe-only or Mock.
func NewRiskEvaluator() RiskEvaluator {
	tsKey := strings.TrimSpace(os.Getenv("TYPESAFE_API_KEY"))
	evalKey := strings.TrimSpace(os.Getenv("EVALUATOR_API_KEY"))
	apiURL := strings.TrimSpace(os.Getenv("EVALUATOR_API_URL"))

	if evalKey != "" && apiURL == "" {
		log.Fatal("EVALUATOR_API_KEY set but EVALUATOR_API_URL is empty")
	}

	if apiURL != "" && evalKey != "" {
		httpEv := newHTTPRiskEvaluator(apiURL, evalKey)
		if tsKey != "" {
			base := strings.TrimSpace(os.Getenv("TYPESAFE_BASE_URL"))
			model := strings.TrimSpace(os.Getenv("TYPESAFE_DEFAULT_MODEL"))
			ts := NewTypeSafeEvaluator(tsKey, base, model)
			log.Printf("evaluator: HTTP %s (timeout %s), TypeSafe fallback %s", apiURL, evaluatorHTTPTimeout, ts.baseURL)
			return &fallbackRiskEvaluator{primary: httpEv, fallback: ts}
		}
		log.Printf("evaluator: HTTP %s (timeout %s)", apiURL, evaluatorHTTPTimeout)
		return httpEv
	}

	if tsKey != "" {
		base := strings.TrimSpace(os.Getenv("TYPESAFE_BASE_URL"))
		model := strings.TrimSpace(os.Getenv("TYPESAFE_DEFAULT_MODEL"))
		ev := NewTypeSafeEvaluator(tsKey, base, model)
		log.Printf("evaluator: TypeSafe %s model=%s (timeout %s)", ev.baseURL, ev.model, ev.timeout)
		return ev
	}

	log.Println("evaluator: mock (no EVALUATOR_API_KEY or TYPESAFE_API_KEY)")
	return MockRiskEvaluator{}
}
