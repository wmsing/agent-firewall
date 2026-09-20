# agent-firewall

**Language**: **English** | [简体中文](README.zh-CN.md)

> **One line**: Before an agent hits HTTP or runs shell, traffic goes through one policy stack—**fail-closed** if checks do not pass.

**Repository**: <https://github.com/wmsing/agent-firewall>

---

## Contents

| I want to… | Go to |
|------------|--------|
| Clone and run tests | [Quick start](#quick-start) |
| Run the HTTP gateway | [L7 gateway](#l7-gateway) |
| Wire Cursor MCP | [MCP (Cursor)](#mcp-cursor) |
| Configure semantic scoring | [Environment](#environment-variables) |
| Understand the two layers | [Architecture](#architecture) |
| View the interactive diagram | [Architecture](#architecture) · [Open HTML locally](#viewing-the-architecture-diagram) |
| OWASP / threat model | [Threat model](#threat-model--owasp-for-llm-alignment) |
| Edit hard rules | [Architecture](#architecture) · [`eval/rules.json`](eval/rules.json) |

---

## Architecture

| Layer | Process | Inspected payload | When to use |
|-------|---------|-----------------|-------------|
| **L7** | `agent-firewall` → `:8286` | POST/PUT/DELETE bodies | Agents use REST as tools |
| **MCP** | `mcp-firewall` (stdio) | `execute_bash_command` strings | Cursor / Claude terminal tools |

**Shared `eval` package**

1. **Hard rules** — `DROP TABLE`, `TRUNCATE`, `rm -rf`, dangerous `git` ops, etc. → **BLOCK** ([`eval/rules.json`](eval/rules.json), `go:embed`; rebuild or restart MCP after edits)  
2. **Semantic score** — Mock or HTTP evaluator; **score ≥ 0.8** → **BLOCK**

```text
  HTTP (POST/PUT/DEL) ──► :8286 ──► hard rules → score ──► upstream API
  GET passthrough · body > 1MB → 413

  MCP execute_bash_* ──► mcp-firewall ──► same eval ──► /bin/bash -c
  BLOCK → isError + reason
```

**Diagram (Archify)**: source [`docs/diagrams/agent-firewall.architecture.json`](docs/diagrams/agent-firewall.architecture.json) · standalone [`docs/diagrams/agent-firewall-architecture.html`](docs/diagrams/agent-firewall-architecture.html)

### Viewing the architecture diagram

GitHub **does not run** HTML from the repo. After clone, open in a browser:

```bash
open docs/diagrams/agent-firewall-architecture.html   # macOS
# Linux: xdg-open docs/diagrams/agent-firewall-architecture.html
# Windows: start docs/diagrams/agent-firewall-architecture.html
```

Or double-click the file in your file manager. Regenerate HTML from JSON with Archify `deliver` after edits.

---

## Threat Model & OWASP for LLM Alignment

`agent-firewall` is engineered to defend against key risks defined in the **OWASP Top 10 for LLM Applications**:

| OWASP LLM Category | Attack Vector | Firewall Defense Mechanism |
| :--- | :--- | :--- |
| **LLM01: Prompt Injection** | Malicious payloads via HTTP tools | Semantic risk scoring (TypeSafe Jev) → 403 Forbidden |
| **LLM06: Excessive Agency** | Agent running destructive host commands | MCP Executor blocks `rm -rf`, dangerous Git ops |
| **LLM02: Sensitive Info Disclosure** | Unauthorized credential access | Hard-rule regex & semantic interception |
| **LLM04: Model DoS** | OOM attacks via oversized payloads | Strict 1MB payload ceiling → 413 Payload Too Large |

---

## Quick start

**Requires**: Go **1.22+**

```bash
git clone https://github.com/wmsing/agent-firewall.git
cd agent-firewall
make check-firewall    # integration script + go test
```

Optional:

```bash
make test              # unit tests only
make e2e-pocketbase    # needs local pocketbase; or POCKETBASE=/path/to/pocketbase
```

---

## L7 gateway

```bash
go run .                                    # :8286 → built-in mock :8287
go run . -backend=false -target http://127.0.0.1:8090
```

---

## MCP (Cursor)

### Checklist

- [ ] Copy `.cursor/mcp.json.example` → `.cursor/mcp.json` (`scripts/run-mcp-firewall.sh`; **Reload MCP** after Cursor agent rules change; rebuild/restart MCP after **hard rule** edits in `eval/rules.json`)
- [ ] Parent monorepo `jev_demo`: use `jev_demo/.cursor/mcp.json` (paths under `agent-firewall/scripts/...`); do not use bare `go run ./cmd/mcp-firewall` from monorepo root
- [ ] Production/CI binary: `go build -o mcp-firewall ./cmd/mcp-firewall`, point `command` at the binary

See `.cursor/mcp.json.example` (detects `agent-firewall` vs `jev_demo` workspace layout).

- [ ] Monorepo errors: ensure logs are not `stat .../jev_demo/cmd/mcp-firewall` (stale config); Reload MCP
- [ ] `go: command not found`: set `env.PATH` in `mcp.json` (e.g. Homebrew) or use absolute path to `go`
- [ ] Agent rules (`alwaysApply` recommended): shell **only** via `execute_bash_command`; on `isError: true` or `firewall BLOCK` → **stop**, do not bypass

**Smoke test** (expect `firewall BLOCK [hard_rule]: rm_rf` and `"isError":true`):

```bash
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_bash_command","arguments":{"command":"rm -rf /"}}}' | go run ./cmd/mcp-firewall
```

---

## Environment variables

Copy `.env.example` → `.env` (**do not commit**)

| Variable | Empty / unset | When set |
|----------|---------------|----------|
| `TYPESAFE_API_KEY` | — | **Preferred**: native TypeSafe `/v1/systemone` (Jev) |
| `TYPESAFE_BASE_URL` | `https://api.typesafe.ai` | API base URL |
| `TYPESAFE_DEFAULT_MODEL` | `jev-latest` | System One model |
| `TYPESAFE_EVALUATOR_TIMEOUT` | `2s` | Per-eval timeout |
| `EVALUATOR_API_KEY` | Mock if no TypeSafe key | Generic HTTP evaluator |
| `EVALUATOR_API_URL` | — | POST target when `EVALUATOR_API_KEY` is set |

---

## License

No `LICENSE` file yet. Add one before external use and update this section.
