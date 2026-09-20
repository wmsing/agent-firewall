package main

import (
	"bytes"
	"encoding/json"
	"github.com/wmsing/agent-firewall/eval"
	"strings"
	"testing"
)

func TestMCP_blockDangerousCommand(t *testing.T) {
	in := strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"execute_bash_command","arguments":{"command":"rm -rf /tmp/x"}}}` + "\n")
	var out bytes.Buffer
	runMCP(in, &out, eval.MockRiskEvaluator{})

	var resp rpcResponse
	if err := json.NewDecoder(&out).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error != nil {
		t.Fatalf("rpc error: %v", resp.Error)
	}
	raw, _ := json.Marshal(resp.Result)
	if !strings.Contains(string(raw), "BLOCK") || !strings.Contains(string(raw), "isError") {
		t.Fatalf("want block tool result, got %s", raw)
	}
}

func TestMCP_initializeAndList(t *testing.T) {
	in := strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}` + "\n" +
			`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}` + "\n",
	)
	var out bytes.Buffer
	runMCP(in, &out, eval.MockRiskEvaluator{})

	dec := json.NewDecoder(&out)
	var r1 rpcResponse
	if err := dec.Decode(&r1); err != nil {
		t.Fatal(err)
	}
	if r1.Error != nil {
		t.Fatal(r1.Error)
	}
	var r2 rpcResponse
	if err := dec.Decode(&r2); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(r2.Result)
	if !strings.Contains(string(raw), toolName) {
		t.Fatalf("tools/list missing %s: %s", toolName, raw)
	}
}
