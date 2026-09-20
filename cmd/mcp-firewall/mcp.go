package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"github.com/wmsing/agent-firewall/eval"
	"io"
	"os"
	"os/exec"
	"strings"
)

const toolName = "execute_bash_command"

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type toolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

type toolCallArgs struct {
	Command string `json:"command"`
}

type toolResult struct {
	Content []contentBlock `json:"content"`
	IsError bool           `json:"isError,omitempty"`
}

type contentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type server struct {
	eval eval.RiskEvaluator
	out  io.Writer
}

func (s *server) write(v interface{}) {
	_ = json.NewEncoder(s.out).Encode(v)
}

func (s *server) handle(ctx context.Context, req rpcRequest) {
	if req.JSONRPC != "2.0" {
		return
	}
	switch req.Method {
	case "initialize":
		s.write(rpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]interface{}{
				"protocolVersion": "2024-11-05",
				"capabilities": map[string]interface{}{
					"tools": map[string]interface{}{},
				},
				"serverInfo": map[string]string{
					"name":    "mcp-firewall",
					"version": "0.1.0",
				},
			},
		})
	case "notifications/initialized", "initialized":
		// notification, no response
	case "tools/list":
		s.write(rpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]interface{}{
				"tools": []map[string]interface{}{
					{
						"name":        toolName,
						"description": "Run a shell command after firewall hard-rule and semantic risk checks (threshold 0.8).",
						"inputSchema": map[string]interface{}{
							"type": "object",
							"properties": map[string]interface{}{
								"command": map[string]string{"type": "string"},
							},
							"required": []string{"command"},
						},
					},
				},
			},
		})
	case "tools/call":
		s.handleToolCall(ctx, req)
	default:
		if len(req.ID) == 0 {
			return
		}
		s.write(rpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &rpcError{Code: -32601, Message: "method not found: " + req.Method},
		})
	}
}

func (s *server) handleToolCall(ctx context.Context, req rpcRequest) {
	var p toolCallParams
	if err := json.Unmarshal(req.Params, &p); err != nil || p.Name != toolName {
		s.write(rpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &rpcError{Code: -32602, Message: "invalid tool call params"},
		})
		return
	}
	var args toolCallArgs
	if err := json.Unmarshal(p.Arguments, &args); err != nil || strings.TrimSpace(args.Command) == "" {
		s.write(rpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: toolResult{
				IsError: true,
				Content: []contentBlock{{Type: "text", Text: "missing required argument: command"}},
			},
		})
		return
	}

	body := []byte(args.Command)
	blocked, layer, reason, score := eval.Assess(ctx, s.eval, body)
	if blocked {
		msg := fmt.Sprintf("firewall BLOCK [%s]: %s", layer, reason)
		if score != nil {
			msg += fmt.Sprintf(" (score=%.2f)", *score)
		}
		s.write(rpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: toolResult{
				IsError: true,
				Content: []contentBlock{{Type: "text", Text: msg}},
			},
		})
		return
	}

	cmd := exec.CommandContext(ctx, "/bin/bash", "-c", args.Command)
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	text := string(out)
	if err != nil {
		text = strings.TrimSpace(text)
		if text != "" {
			text += "\n"
		}
		text += err.Error()
		s.write(rpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: toolResult{
				IsError: true,
				Content: []contentBlock{{Type: "text", Text: text}},
			},
		})
		return
	}
	s.write(rpcResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: toolResult{
			Content: []contentBlock{{Type: "text", Text: text}},
		},
	})
}

func runMCP(in io.Reader, out io.Writer, ev eval.RiskEvaluator) {
	s := &server{eval: ev, out: out}
	sc := bufio.NewScanner(in)
	// ponytail: 1MB line cap for JSON-RPC frames
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	ctx := context.Background()
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			continue
		}
		s.handle(ctx, req)
	}
}
