package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/wmsing/agent-firewall/eval"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

const maxBodyBytes = 1 << 20 // 1MB

type blockResponse struct {
	Error  string   `json:"error"`
	Layer  string   `json:"layer"`
	Reason string   `json:"reason"`
	Score  *float64 `json:"score,omitempty"`
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func auditDecision(r *http.Request, action, reason string, score *float64) {
	attrs := []any{
		"client_ip", clientIP(r),
		"method", r.Method,
		"path", r.URL.Path,
		"reason", reason,
		"action", action,
	}
	if score != nil {
		attrs = append(attrs, "risk_score", *score)
	}
	slog.Info("firewall", attrs...)
}

func writeBlock(w http.ResponseWriter, r *http.Request, layer, reason string, score *float64) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(blockResponse{
		Error:  "forbidden",
		Layer:  layer,
		Reason: reason,
		Score:  score,
	})
	auditDecision(r, "BLOCK", reason, score)
}

func writePayloadTooLarge(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusRequestEntityTooLarge)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":  "payload_too_large",
		"reason": "body exceeds 1MB",
	})
	auditDecision(r, "BLOCK", "payload_too_large", nil)
}

func mutatingMethod(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodPost, http.MethodPut, http.MethodDelete:
		return true
	default:
		return false
	}
}

func NewFirewallHandler(target *url.URL, ev eval.RiskEvaluator) http.Handler {
	proxy := httputil.NewSingleHostReverseProxy(target)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !mutatingMethod(r.Method) {
			proxy.ServeHTTP(w, r)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				writePayloadTooLarge(w, r)
				return
			}
			writeBlock(w, r, "pipeline", "failed to read request body", nil)
			return
		}
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))

		blocked, layer, reason, score := eval.Assess(r.Context(), ev, body)
		if blocked {
			writeBlock(w, r, layer, reason, score)
			return
		}

		auditDecision(r, "ALLOW", reason, score)
		proxy.ServeHTTP(w, r)
	})
}
